use base64::{engine::general_purpose, Engine as _};

use crate::{
    crypto::{aes_cbc_decrypt, aes_cbc_encrypt, dyn_encode, ARGUS_SIGN_KEY},
    error::{Error, Result},
    persona::{parse_optional_u64, Persona},
    sm3::sm3,
};

const MASK: u64 = u64::MAX;
const Z4_BITS: &[u8] = b"11010001111001101011011000100000010111000011001010010011101111110100";
const DEFAULT_HEADER: [u8; 9] = [0xec, 0xc5, 0x58, 0x2d, 0x37, 0x01, 0x9c, 0x03, 0x18];
const DEFAULT_TRAILER: [u8; 13] = [
    0x48, 0x22, 0x8a, 0x29, 0xa7, 0x9e, 0x78, 0xe0, 0x80, 0x00, 0x00, 0xf5, 0x0d,
];

#[inline]
fn rol64(x: u64, r: u32) -> u64 {
    x.rotate_left(r)
}

#[inline]
fn ror64(x: u64, r: u32) -> u64 {
    x.rotate_right(r)
}

fn simon_key_schedule(key32: &[u8; 32]) -> [u64; 72] {
    let mut k = [0u64; 72];
    for i in 0..4 {
        k[i] = u64::from_le_bytes(key32[i * 8..i * 8 + 8].try_into().unwrap());
    }
    for i in 4..72 {
        let z = (Z4_BITS[i - 4] - b'0') as u64;
        let c_z = (MASK - 3) ^ z;
        let tmp = ror64(k[i - 1], 3) ^ k[i - 3];
        let tmp = tmp ^ ror64(tmp, 1);
        k[i] = c_z ^ k[i - 4] ^ tmp;
    }
    k
}

fn simon_encrypt_block(block: &[u8], round_keys: &[u64; 72]) -> [u8; 16] {
    let mut y = u64::from_le_bytes(block[..8].try_into().unwrap());
    let mut x = u64::from_le_bytes(block[8..16].try_into().unwrap());
    for rk in round_keys {
        let next = ((rol64(x, 1) & rol64(x, 8)) ^ y ^ rol64(x, 2) ^ rk) & MASK;
        y = x;
        x = next;
    }
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&y.to_le_bytes());
    out[8..].copy_from_slice(&x.to_le_bytes());
    out
}

fn simon_decrypt_block(block: &[u8], round_keys: &[u64; 72]) -> [u8; 16] {
    let mut y = u64::from_le_bytes(block[..8].try_into().unwrap());
    let mut x = u64::from_le_bytes(block[8..16].try_into().unwrap());
    for rk in round_keys.iter().rev() {
        let x_old = y;
        let y_old = x ^ (rol64(x_old, 1) & rol64(x_old, 8)) ^ rol64(x_old, 2) ^ rk;
        y = y_old;
        x = x_old;
    }
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&y.to_le_bytes());
    out[8..].copy_from_slice(&x.to_le_bytes());
    out
}

fn simon_ecb(data: &[u8], keys: &[u64; 72], decrypt: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks(16) {
        if decrypt {
            out.extend_from_slice(&simon_decrypt_block(block, keys));
        } else {
            out.extend_from_slice(&simon_encrypt_block(block, keys));
        }
    }
    out
}

pub fn derive_simon_key(rnd4: &[u8; 4]) -> [u8; 32] {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&ARGUS_SIGN_KEY);
    data.extend_from_slice(rnd4);
    data.extend_from_slice(&ARGUS_SIGN_KEY);
    sm3(&data)
}

pub fn vm_checksum(data: &[u8]) -> u32 {
    let mut state = 0u32;
    for (index, byte) in data.iter().enumerate() {
        if index & 1 == 1 {
            let work = (*byte as u32) | state.wrapping_shl(11);
            let work = work ^ (state >> 5) ^ state;
            state = !work;
        } else {
            let work = (*byte as u32) ^ state.wrapping_shl(7) ^ (state >> 3);
            state ^= work;
        }
    }
    state
}

pub fn key4_from_rnd4(rnd4: &[u8; 4]) -> [u8; 4] {
    vm_checksum(&rnd4[2..]).to_be_bytes()
}

#[derive(Default)]
struct ProtoWriter {
    bytes: Vec<u8>,
}

impl ProtoWriter {
    fn varint(&mut self, value: u64) {
        let mut value = value;
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.bytes.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn field_varint(&mut self, number: u32, value: u64) {
        self.varint((number as u64) << 3);
        self.varint(value);
    }

    fn field_bytes(&mut self, number: u32, value: &[u8]) {
        self.varint(((number as u64) << 3) | 2);
        self.varint(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn nested(&mut self, number: u32, value: ProtoWriter) {
        self.field_bytes(number, &value.bytes);
    }
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn device_token(persona: &Persona) -> String {
    if let Some(token) = &persona.device_token {
        return token.clone();
    }
    format!(
        "{{\"device_id\":\"{}\",\"install_id\":\"{}\",\"channel\":\"{}\",\"app_version\":\"{}\",\"os\":\"Android\",\"os_version\":\"{}\",\"device_type\":\"{}\",\"device_brand\":\"google\",\"resolution\":\"{}\",\"dpi\":{},\"rom\":\"{}\",\"host_abi\":\"arm64-v8a\"}}",
        json_escape(&persona.device_id),
        json_escape(&persona.install_id),
        json_escape(&persona.channel),
        json_escape(&persona.app_version),
        json_escape(&persona.release),
        json_escape(&persona.model),
        json_escape(&persona.resolution),
        persona.dpi,
        json_escape(&persona.build),
    )
}

pub fn build_protobuf(
    persona: &Persona,
    query_for_argus: &str,
    body_stub: &[u8],
    khronos: u64,
    nonce: u32,
) -> Result<Vec<u8>> {
    let mut p = ProtoWriter::default();
    p.field_varint(1, 0x2020_0929u64 << 1);
    p.field_varint(2, 2);
    p.field_varint(3, (nonce as u64) << 1);
    p.field_bytes(4, persona.app_id.as_bytes());
    p.field_bytes(6, persona.license_id.to_string().as_bytes());
    p.field_bytes(7, persona.app_version.as_bytes());
    p.field_bytes(8, persona.sdk_version.as_bytes());
    p.field_varint(9, persona.sdk_version_code << 1);
    p.field_bytes(10, &[0; 8]);
    p.field_varint(12, khronos << 1);
    p.field_bytes(13, &sm3(body_stub)[..6]);
    p.field_bytes(14, &sm3(query_for_argus.as_bytes())[..6]);

    let mut f15 = ProtoWriter::default();
    f15.field_varint(1, 6);
    f15.field_varint(5, 2);
    f15.field_varint(6, 112);
    f15.field_varint(7, khronos << 1);
    p.nested(15, f15);
    p.field_bytes(16, device_token(persona).as_bytes());
    p.field_varint(17, khronos << 1);
    p.field_bytes(20, b"none");
    p.field_varint(21, 624);

    let mut f23 = ProtoWriter::default();
    f23.field_bytes(1, persona.model.as_bytes());
    f23.field_varint(2, persona.f23_field2);
    f23.field_bytes(3, persona.channel.as_bytes());
    f23.field_varint(4, persona.f23_field4);
    f23.field_varint(5, persona.f23_field5);
    p.nested(23, f23);

    p.field_varint(25, persona.seed_state() << 1);
    if let Some(seed) = &persona.dyn_seed {
        p.field_bytes(24, seed.as_bytes());
        let mut entry = ProtoWriter::default();
        entry.field_varint(1, (persona.dyn_version() as u64) << 1);
        let encoded = dyn_encode(
            persona.dyn_version(),
            query_for_argus.as_bytes(),
            body_stub,
            nonce,
        )?;
        entry.field_bytes(2, &encoded);
        p.nested(26, entry);
        p.field_varint(28, 10);
    }
    if let Some(tail) = &persona.f26_tail {
        for item in tail {
            let mut entry = ProtoWriter::default();
            entry.field_varint(1, (item.algorithm as u64) << 1);
            entry.field_bytes(2, &hex::decode(&item.output_hex)?);
            p.nested(26, entry);
        }
    }
    p.field_varint(29, 2);
    p.field_varint(30, 8);
    p.field_varint(
        31,
        ((persona.env_salt32 ^ nonce ^ (khronos as u32)) as u64) << 1,
    );
    if let Some(blob) = &persona.session_blob_hex {
        p.field_bytes(32, &hex::decode(blob)?);
    }
    p.field_varint(33, persona.rsk2_ms << 1);
    p.field_varint(
        34,
        parse_optional_u64(&persona.f34)?
            .unwrap_or_else(|| (rand::random::<u64>() & 0x1fff_ffff_ffff_ffff) << 1),
    );
    p.field_varint(
        35,
        parse_optional_u64(&persona.f35)?.unwrap_or_else(|| {
            let low = (rand::random::<u32>() & 0x7f0f_87ff) | 0x0080_0000;
            ((((khronos / 60) & 0x3f) << 58) | (2u64 << 46) | low as u64) << 1
        }),
    );
    p.field_varint(
        36,
        parse_optional_u64(&persona.f36)?.unwrap_or_else(|| {
            let high = (rand::random::<u64>() & 0x7fff_ffff) << 32;
            let low = rand::random::<u32>() as u64;
            (high | low) << 1
        }),
    );
    Ok(p.bytes)
}

pub fn encrypt_argus(
    protobuf: &[u8],
    header: &[u8; 9],
    key4: &[u8; 4],
    rnd4: &[u8; 4],
    trailer: &[u8; 13],
) -> String {
    let pad = 16 - protobuf.len() % 16;
    let mut padded = Vec::with_capacity(protobuf.len() + pad);
    padded.extend_from_slice(protobuf);
    padded.resize(protobuf.len() + pad, pad as u8);
    let keys = simon_key_schedule(&derive_simon_key(rnd4));
    let simon = simon_ecb(&padded, &keys, false);
    let mut buf = Vec::with_capacity(simon.len() + 8);
    buf.extend(simon.iter().rev());
    buf.extend_from_slice(&[0; 8]);
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte ^= key4[i % 4];
    }
    let mut pre = Vec::with_capacity(9 + buf.len() + 2 + 13);
    pre.extend_from_slice(header);
    pre.extend_from_slice(&buf);
    pre.extend_from_slice(&rnd4[2..]);
    pre.extend_from_slice(trailer);
    let ciphertext = aes_cbc_encrypt(&pre);
    let mut token = Vec::with_capacity(2 + ciphertext.len());
    token.extend_from_slice(&rnd4[..2]);
    token.extend_from_slice(&ciphertext);
    general_purpose::STANDARD.encode(token)
}

#[derive(Debug)]
pub struct ArgusParts {
    pub protobuf: Vec<u8>,
    pub header: [u8; 9],
    pub key4: [u8; 4],
    pub rnd4: [u8; 4],
    pub trailer: [u8; 13],
}

pub fn decrypt_argus(token_b64: &str) -> Result<ArgusParts> {
    let token = general_purpose::STANDARD.decode(token_b64)?;
    if token.len() < 2 + 16 {
        return Err(Error::InvalidArgument("Argus token is too short".into()));
    }
    let plaintext = aes_cbc_decrypt(&token[2..])?;
    if plaintext.len() < 9 + 8 + 2 + 13 {
        return Err(Error::InvalidArgument(
            "Argus plaintext is too short".into(),
        ));
    }
    let header: [u8; 9] = plaintext[..9].try_into().unwrap();
    let buf = &plaintext[9..plaintext.len() - 15];
    let mut rnd4 = [0u8; 4];
    rnd4[..2].copy_from_slice(&token[..2]);
    rnd4[2..].copy_from_slice(&plaintext[plaintext.len() - 15..plaintext.len() - 13]);
    let trailer: [u8; 13] = plaintext[plaintext.len() - 13..].try_into().unwrap();
    if buf.len() < 8 {
        return Err(Error::InvalidArgument("Argus buffer is too short".into()));
    }
    let key4: [u8; 4] = buf[buf.len() - 8..buf.len() - 4].try_into().unwrap();
    let unxored: Vec<u8> = buf
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key4[i % 4])
        .collect();
    if unxored[unxored.len() - 8..] != [0; 8] {
        return Err(Error::InvalidArgument(
            "Argus trailing zero bytes missing".into(),
        ));
    }
    let reversed: Vec<u8> = unxored[..unxored.len() - 8].iter().rev().copied().collect();
    let keys = simon_key_schedule(&derive_simon_key(&rnd4));
    let padded = simon_ecb(&reversed, &keys, true);
    let pad = *padded.last().ok_or(Error::Padding)? as usize;
    if pad == 0 || pad > 16 || pad > padded.len() {
        return Err(Error::Padding);
    }
    Ok(ArgusParts {
        protobuf: padded[..padded.len() - pad].to_vec(),
        header,
        key4,
        rnd4,
        trailer,
    })
}

pub fn default_header() -> [u8; 9] {
    DEFAULT_HEADER
}

pub fn default_trailer() -> [u8; 13] {
    DEFAULT_TRAILER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simon_key_checksum_vectors() {
        assert_eq!(vm_checksum(&ARGUS_SIGN_KEY), 0x7376_16ec);
        assert_eq!(
            key4_from_rnd4(&[0xb4, 0xc5, 0xe7, 0x20]),
            [0xff, 0xf8, 0xc7, 0x3f]
        );
        assert_eq!(
            key4_from_rnd4(&[0x92, 0xdc, 0xa6, 0x6a]),
            [0xff, 0xfa, 0xcf, 0x36]
        );
        assert_eq!(
            key4_from_rnd4(&[0xf1, 0xfb, 0x02, 0x09]),
            [0xff, 0xff, 0xef, 0xf4]
        );
    }

    #[test]
    fn native_argus_round_trip() {
        let token = "8fvvl9FBuceE7A90navMO3zbvgpdoPlLe3ZZtV3zgyOpBOwwMQDFsUr14jCIVNprkim047xhrRpUonDwpI8crvW0ZqhfT6whDgUCGoWEBM35DRnfMEcjl7DoFjVb1mI84Plw11wjLGsw5u7oZa15v7U4u18BXRCMCtbuqZ068YME4rYokaoOhbEOoZHBgpfUJW2JI5kYfa7HpJvmKkaeFYN8wFdpigQThzfrEdmJlCA4f5XAYrZ7pMTcUUSsq7xXZrLJ+g5LtOMb/xw6FdsTFZI+C50wSL7RUzUG1gJNN7V7tFlzGrJtZGwuGObd9HCrnLmjuDmPvJIqcXq55QM7F6d4wPdO5CziBnWNbG45mnGpJfrxiKbnYOUwgWoPclhsC/PqXg8PSx7cqYEdTkOYblvepkqooNuxZY7rDYXAjkd/z2/KE6lMuaoVNeiYVCeZb421dI3QwrJAuyybvjj7nt04v8cph+nW+sFQWveAeBypdfNB+gwXSVgUdc/XhPV4W315KLM+dpQBURBxex7fUbYf0Sr7h0niMt1tEi24OsjHlHOq853Unpvrx3YYoEIANdlFiWnm7X3xsaB6FbsIbyA09DAnfbTx/V+2vZbUoAETPz2DzNxmnIXcJDIuD0QZDyrRSQ4TjTjtLJ4QCCiW6XgQkoo8z/KY6nl5fd7VDNBWjThvwPUltvZmdmXxBlh0TIq3dl3DLO+RVc+FjND10z0y";
        let parts = decrypt_argus(token).unwrap();
        assert_eq!(parts.rnd4, [0xf1, 0xfb, 0x02, 0x09]);
        assert_eq!(parts.key4, [0xff, 0xff, 0xef, 0xf4]);
        let rebuilt = encrypt_argus(
            &parts.protobuf,
            &parts.header,
            &parts.key4,
            &parts.rnd4,
            &parts.trailer,
        );
        assert_eq!(rebuilt, token);
    }
}
