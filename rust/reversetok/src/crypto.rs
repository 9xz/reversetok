use std::collections::VecDeque;

use aes::cipher::{BlockEncrypt, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::{Digest, Md5};

use crate::{
    error::{Error, Result},
    sm3::sm3,
};

pub const ARGUS_SIGN_KEY: [u8; 32] = [
    0xc0, 0x2f, 0x25, 0x0f, 0x86, 0xcc, 0x4f, 0x19, 0x8d, 0x57, 0x06, 0x39, 0x8d, 0x29, 0x2a, 0x8b,
    0x74, 0x16, 0x9a, 0xba, 0x61, 0xaf, 0xfe, 0x7c, 0xba, 0x02, 0xe4, 0xa3, 0xb5, 0x19, 0x81, 0x63,
];
pub const ARGUS_AES_KEY: [u8; 16] = [
    0x82, 0x52, 0x97, 0x0d, 0x95, 0x9b, 0x06, 0xdb, 0x10, 0x2e, 0x17, 0xd8, 0x5c, 0x0e, 0xc1, 0xaf,
];
pub const ARGUS_AES_IV: [u8; 16] = [
    0x4d, 0x20, 0x7e, 0xa3, 0x7a, 0x41, 0x9f, 0x7d, 0x62, 0x2f, 0x81, 0xc6, 0xa2, 0xf5, 0x35, 0x94,
];
const GORGON_PREFIX: [u8; 6] = [0x84, 0x04, 0xa0, 0x97, 0x00, 0x00];
const GORGON_KEYSTREAM: [u8; 20] = [
    0xa7, 0xfd, 0xd6, 0xa3, 0xa4, 0xa7, 0xb6, 0xaf, 0xbb, 0xc5, 0xfd, 0xa4, 0xd7, 0x6e, 0xa4, 0xf0,
    0xdb, 0xf5, 0xf2, 0xf0,
];
const LADON_MASK: u64 = u64::MAX;

pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let digest = Md5::digest(data);
    digest.into()
}

pub fn md5_hex(data: &[u8]) -> String {
    hex::encode(md5_bytes(data))
}

pub fn aes_cbc_encrypt(data: &[u8]) -> Vec<u8> {
    cbc::Encryptor::<aes::Aes128>::new(&ARGUS_AES_KEY.into(), &ARGUS_AES_IV.into())
        .encrypt_padded_vec_mut::<NoPadding>(data)
}

pub fn aes_cbc_decrypt(data: &[u8]) -> Result<Vec<u8>> {
    cbc::Decryptor::<aes::Aes128>::new(&ARGUS_AES_KEY.into(), &ARGUS_AES_IV.into())
        .decrypt_padded_vec_mut::<NoPadding>(data)
        .map_err(|_| Error::Padding)
}

fn aes_ofb_last4(data: &[u8], key_ascii: &[u8]) -> u32 {
    let mut key = [0u8; 16];
    key.copy_from_slice(&key_ascii[..16]);
    let mut state = [0u8; 16];
    state.copy_from_slice(&key_ascii[16..32]);
    let cipher = aes::Aes128::new((&key).into());
    let mut padded = Vec::with_capacity(data.len() + 16);
    padded.extend_from_slice(data);
    let pad = 16 - data.len() % 16;
    padded.resize(data.len() + pad, pad as u8);
    let mut output = Vec::with_capacity(padded.len());
    for block in padded.chunks_exact(16) {
        cipher.encrypt_block((&mut state).into());
        for (a, b) in block.iter().zip(state) {
            output.push(a ^ b);
        }
    }
    u32::from_le_bytes(output[output.len() - 4..].try_into().unwrap())
}

fn reverse_nibble(x: u8) -> u8 {
    x.rotate_right(4)
}

fn gorgon_handle(data: &[u8; 20]) -> [u8; 20] {
    let mut out = *data;
    for i in 0..20 {
        let a = out[i];
        let b = reverse_nibble(a);
        let c = out[(i + 1) % 20];
        let d = b ^ c;
        let e = d.reverse_bits();
        out[i] = !(e ^ 20);
    }
    out
}

pub fn gorgon(query: &str, khronos: u64, stub: Option<&[u8]>) -> String {
    let mut input = [0u8; 20];
    input[..4].copy_from_slice(&md5_bytes(query.as_bytes())[..4]);
    if let Some(stub) = stub {
        input[4..8].copy_from_slice(&stub[..4]);
    }
    input[16..20].copy_from_slice(&(khronos as u32).to_be_bytes());
    let mixed = std::array::from_fn::<u8, 20, _>(|i| input[i] ^ GORGON_KEYSTREAM[i]);
    let transformed = gorgon_handle(&mixed);
    let mut token = Vec::with_capacity(26);
    token.extend_from_slice(&GORGON_PREFIX);
    token.extend_from_slice(&transformed);
    hex::encode(token)
}

fn ror64(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

fn ladon_schedule(random4: &[u8; 4], aid: u64) -> [u64; 36] {
    let md5_ascii = md5_hex(&[random4.as_slice(), aid.to_string().as_bytes()].concat());
    let mut words = [0u64; 4];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u64::from_le_bytes(md5_ascii.as_bytes()[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let mut left = words[0];
    let mut right = words[1];
    let mut queue = VecDeque::from([words[2], words[3]]);
    let mut keys = [0u64; 36];
    keys[..4].copy_from_slice(&words);
    for round in 0..34u64 {
        let mut value = ror64(right, 8).wrapping_add(left) & LADON_MASK;
        value ^= round;
        queue.push_back(value);
        value ^= ror64(left, 61);
        keys[round as usize + 1] = value;
        left = value;
        right = queue.pop_front().unwrap();
    }
    keys
}

fn ladon_encrypt_block(keys: &[u64; 36], block: &[u8]) -> [u8; 16] {
    let mut left = u64::from_le_bytes(block[..8].try_into().unwrap());
    let mut right = u64::from_le_bytes(block[8..16].try_into().unwrap());
    for key in keys.iter().take(34) {
        right = key ^ left.wrapping_add(ror64(right, 8));
        left = right ^ ror64(left, 61);
    }
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&left.to_le_bytes());
    out[8..].copy_from_slice(&right.to_le_bytes());
    out
}

fn ladon_decrypt_block(keys: &[u64; 36], block: &[u8]) -> [u8; 16] {
    let mut left = u64::from_le_bytes(block[..8].try_into().unwrap());
    let mut right = u64::from_le_bytes(block[8..16].try_into().unwrap());
    for key in keys.iter().take(34).rev() {
        let previous_left = (left ^ right).rotate_left(61);
        let previous_right = (right ^ key).wrapping_sub(previous_left).rotate_left(8);
        left = previous_left;
        right = previous_right;
    }
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&left.to_le_bytes());
    out[8..].copy_from_slice(&right.to_le_bytes());
    out
}

pub fn ladon(khronos: u64, license_id: u64, aid: u64, random4: [u8; 4]) -> String {
    let plaintext = format!("{khronos}-{license_id}-{aid}");
    let mut padded = plaintext.into_bytes();
    let pad = 16 - padded.len() % 16;
    padded.resize(padded.len() + pad, pad as u8);
    let keys = ladon_schedule(&random4, aid);
    let mut token = Vec::with_capacity(36);
    token.extend_from_slice(&random4);
    for block in padded.chunks_exact(16) {
        token.extend_from_slice(&ladon_encrypt_block(&keys, block));
    }
    general_purpose::STANDARD.encode(token)
}

pub fn decrypt_ladon(token_b64: &str, aid: u64) -> Result<Vec<u8>> {
    let token = general_purpose::STANDARD.decode(token_b64)?;
    if token.len() != 36 {
        return Err(Error::InvalidArgument(format!(
            "Ladon token must be 36 bytes, got {}",
            token.len()
        )));
    }
    let random4: [u8; 4] = token[..4].try_into().unwrap();
    let keys = ladon_schedule(&random4, aid);
    let mut padded = Vec::with_capacity(32);
    for block in token[4..].chunks_exact(16) {
        padded.extend_from_slice(&ladon_decrypt_block(&keys, block));
    }
    let pad = *padded.last().ok_or(Error::Padding)? as usize;
    if pad == 0
        || pad > 16
        || padded[padded.len() - pad..]
            .iter()
            .any(|b| *b as usize != pad)
    {
        return Err(Error::Padding);
    }
    padded.truncate(padded.len() - pad);
    Ok(padded)
}

fn reverse_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| reverse_nibble(*b)).collect()
}

fn reverse_bits_native(x: u32) -> u32 {
    x.reverse_bits()
}

fn dyn_part_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn dyn_encode(version: u32, params: &[u8], payload: &[u8], rand: u32) -> Result<[u8; 12]> {
    let mut out = [0u8; 12];
    match version {
        1..=4 => {
            let hashes = [
                md5_bytes(&[0, 0, 0, 1]),
                md5_bytes(payload),
                md5_bytes(params),
            ];
            for (i, hash) in hashes.iter().enumerate() {
                let value = match version {
                    1 => u32::from_le_bytes(hash[..4].try_into().unwrap()) ^ rand,
                    2 => {
                        let reversed = reverse_bytes(&hash[..4]);
                        u32::from_le_bytes(reversed.try_into().unwrap()) ^ rand
                    }
                    3 => {
                        let swapped =
                            u32::from_be_bytes(hash[..4].try_into().unwrap()).to_le_bytes();
                        u32::from_be_bytes(swapped) ^ 0x5a5a_5a5a ^ rand
                    }
                    4 => {
                        reverse_bits_native(u32::from_be_bytes(hash[..4].try_into().unwrap()))
                            ^ rand
                    }
                    _ => unreachable!(),
                };
                out[i * 4..i * 4 + 4].copy_from_slice(&dyn_part_be(value));
            }
        }
        5 => {
            let hashes = [sm3(&[0, 0, 0, 1]), sm3(payload), sm3(params)];
            for (i, hash) in hashes.iter().enumerate() {
                let value = u32::from_le_bytes(hash[28..32].try_into().unwrap()) ^ rand;
                out[i * 4..i * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        6 => {
            let key_ascii = md5_hex(&rand.to_be_bytes());
            let values = [
                aes_ofb_last4(&[0, 0, 0, 1], key_ascii.as_bytes()) ^ rand,
                aes_ofb_last4(payload, key_ascii.as_bytes()) ^ rand,
                aes_ofb_last4(params, key_ascii.as_bytes()) ^ rand,
            ];
            for (i, value) in values.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        _ => return Err(Error::UnsupportedDynVersion(version)),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gorgon_native_fixture() {
        let token = gorgon("aid=1233&version_name=47.7.2&probe=alpha", 1793870956, None);
        assert_eq!(
            token,
            "8404a0970000f97345a65cd8c869956e355223a9b696ab1f05e7"
        );
    }

    #[test]
    fn ladon_native_fixture() {
        let token = ladon(1793934086, 2_142_840_551, 1233, [0x65, 0x74, 0x36, 0x35]);
        assert_eq!(token, "ZXQ2NbnqR1PDx6+VAeHnzhRdaByqv3+g7AyGAaLaZE79iNGR");
    }

    #[test]
    fn ladon_round_trip() {
        let token = ladon(1793934086, 2_142_840_551, 1233, [0x65, 0x74, 0x36, 0x35]);
        let plain = decrypt_ladon(&token, 1233).unwrap();
        assert_eq!(plain, b"1793934086-2142840551-1233");
    }

    #[test]
    fn dynamic_version_six_fixture() {
        let params = concat!(
            "os=android&_rticket=1794117955898&is_pad=0&last_install_time=1794102682&host_abi=arm64-v8a&ts=1794117955&effect_sdk_version=22.6.0&req_from=enter_auto&enable_manage_topic_more=false&pull_type=0&app_version=2024707030&is_non_personalized=0&algo_refresh_on=false&",
            "ab_version=47.7.3&ac=mobile&ac2=unknown&aid=1233&app_language=en&app_name=musical_ly&app_type=normal&build_number=47.7.3&carrier_region=US&carrier_region_v2=311&channel=googleplay&current_region=US&device_brand=google&device_id=7705612319771035149&device_platform=android&device_type=Pixel%207%20Pro&dpi=256&iid=7705612484128982798&language=en&locale=en&manifest_version_code=2024707030&mcc_mnc=311480&op_region=US&os_api=36&os_version=16&region=US&residence=US&resolution=720*1560&ssmix=a&sys_region=US&timezone_name=America%2FNew_York&timezone_offset=-18000&uoo=0&update_version_code=2024707030&version_code=470703&version_name=47.7.3",
        );
        let out = dyn_encode(
            6,
            params.as_bytes(),
            &hex::decode("d41d8cd98f00b204e9800998ecf8427e").unwrap(),
            0x53dd58a3,
        )
        .unwrap();
        assert_eq!(hex::encode(out), "72b9d9ce802d1d15e8e103af");
    }

    #[test]
    fn dynamic_version_three_fixture() {
        let out = dyn_encode(
            3,
            b"aid=1233&version_name=47.7.3&probe=fields",
            &hex::decode("d41d8cd98f00b204e9800998ecf8427e").unwrap(),
            0x99f1af9,
        )
        .unwrap();
        assert_eq!(hex::encode(out), "55c605521d77edfa058e14fc");
    }
}
