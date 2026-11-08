use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose, Engine as _};
use flate2::{read::GzDecoder, write::GzEncoder, Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::io::{Read, Write};

use crate::error::{Error, Result};

const PREFIX: [u8; 6] = [0x74, 0x63, 0x05, 0x10, 0, 0];
const KEY_STREAM_LEN: usize = 32;
const KEY_MATERIAL_CONSTANT: [u8; 64] = [
    0x4d, 0xd4, 0xc2, 0xe6, 0xb8, 0x31, 0x62, 0x09, 0x0e, 0x52, 0xb3, 0xc7, 0xa6, 0x73, 0x3b, 0xa4,
    0x1c, 0xb2, 0x46, 0x2b, 0x82, 0x9a, 0xb5, 0x8a, 0x19, 0x6b, 0x39, 0xdb, 0x57, 0x17, 0x75, 0x24,
    0xf4, 0x9b, 0xaf, 0x7f, 0x08, 0xe8, 0xd6, 0x8d, 0x26, 0xa7, 0x2e, 0x37, 0xc1, 0xa9, 0x5a, 0x2f,
    0x1f, 0x05, 0xa5, 0x18, 0x92, 0xae, 0xf2, 0x94, 0x97, 0x32, 0xb6, 0x2a, 0x38, 0xaa, 0xdd, 0x58,
];

fn derive_key_material(key_stream: &[u8; KEY_STREAM_LEN]) -> [u8; 64] {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(&Sha512::digest(key_stream));
    input[64..].copy_from_slice(&KEY_MATERIAL_CONSTANT);
    Sha512::digest(input).into()
}

pub fn tt_encrypt_with_key_stream(
    content: &[u8],
    key_stream: &[u8; KEY_STREAM_LEN],
) -> Result<Vec<u8>> {
    if content.is_empty() {
        return Err(Error::InvalidArgument(
            "TTEncrypt content must not be empty".into(),
        ));
    }
    let material = derive_key_material(key_stream);
    let mut payload = Vec::with_capacity(64 + content.len());
    payload.extend_from_slice(&Sha512::digest(content));
    payload.extend_from_slice(content);
    let ciphertext =
        cbc::Encryptor::<aes::Aes128>::new((&material[..16]).into(), (&material[16..32]).into())
            .encrypt_padded_vec_mut::<Pkcs7>(&payload);
    let mut output = Vec::with_capacity(PREFIX.len() + KEY_STREAM_LEN + ciphertext.len());
    output.extend_from_slice(&PREFIX);
    output.extend_from_slice(key_stream);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn tt_encrypt(content: &[u8]) -> Result<Vec<u8>> {
    tt_encrypt_with_key_stream(content, &rand::random::<[u8; KEY_STREAM_LEN]>())
}

pub fn tt_decrypt(input: &[u8]) -> Result<Vec<u8>> {
    if input.len() < PREFIX.len() + KEY_STREAM_LEN + 16 || !input.starts_with(&PREFIX) {
        return Err(Error::InvalidArgument("invalid TTEncrypt envelope".into()));
    }
    let key_stream: &[u8; KEY_STREAM_LEN] = input[PREFIX.len()..PREFIX.len() + KEY_STREAM_LEN]
        .try_into()
        .unwrap();
    let ciphertext = &input[PREFIX.len() + KEY_STREAM_LEN..];
    if ciphertext.len() % 16 != 0 {
        return Err(Error::InvalidArgument(
            "TTEncrypt ciphertext must be block aligned".into(),
        ));
    }
    let material = derive_key_material(key_stream);
    let decrypted =
        cbc::Decryptor::<aes::Aes128>::new((&material[..16]).into(), (&material[16..32]).into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| Error::Padding)?;
    if decrypted.len() < 64 {
        return Err(Error::InvalidArgument(
            "TTEncrypt plaintext is shorter than its SHA-512 digest".into(),
        ));
    }
    let content = &decrypted[64..];
    if decrypted[..64] != Sha512::digest(content)[..] {
        return Err(Error::InvalidArgument(
            "TTEncrypt content digest mismatch".into(),
        ));
    }
    Ok(content.to_vec())
}

pub fn tt_encrypt_gzip_with_key_stream(
    content: &[u8],
    key_stream: &[u8; KEY_STREAM_LEN],
) -> Result<Vec<u8>> {
    let mut encoder: GzEncoder<Vec<u8>> = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::default());
    encoder
        .write_all(content)
        .map_err(|error| Error::InvalidArgument(format!("gzip compression failed: {error}")))?;
    let compressed = encoder
        .finish()
        .map_err(|error| Error::InvalidArgument(format!("gzip compression failed: {error}")))?;
    tt_encrypt_with_key_stream(&compressed, key_stream)
}

pub fn tt_encrypt_gzip(content: &[u8]) -> Result<Vec<u8>> {
    tt_encrypt_gzip_with_key_stream(content, &rand::random::<[u8; KEY_STREAM_LEN]>())
}

pub fn tt_decrypt_gzip(input: &[u8]) -> Result<Vec<u8>> {
    let compressed = tt_decrypt(input)?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|error| Error::InvalidArgument(format!("gzip decompression failed: {error}")))?;
    Ok(output)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Operation {
    Encrypt,
    Decrypt,
    EncryptGzip,
    DecryptGzip,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TtEncryptInput {
    operation: Operation,
    data_base64: String,
    key_stream_base64: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TtEncryptOutput {
    data_base64: String,
}

pub fn ttencrypt_json(json: &str) -> String {
    crate::json::respond((|| {
        let input: TtEncryptInput = serde_json::from_str(json)?;
        if matches!(
            &input.operation,
            Operation::Decrypt | Operation::DecryptGzip
        ) && input.key_stream_base64.is_some()
        {
            return Err(Error::InvalidArgument(
                "keyStreamBase64 is only valid for encryption".into(),
            ));
        }
        let data = general_purpose::STANDARD.decode(&input.data_base64)?;
        let key_stream = match input.key_stream_base64 {
            Some(value) => Some(
                general_purpose::STANDARD
                    .decode(value)?
                    .try_into()
                    .map_err(|_| {
                        Error::InvalidArgument("keyStreamBase64 must decode to 32 bytes".into())
                    })?,
            ),
            None => None,
        };
        let output = match input.operation {
            Operation::Encrypt => match key_stream {
                Some(key_stream) => tt_encrypt_with_key_stream(&data, &key_stream)?,
                None => tt_encrypt(&data)?,
            },
            Operation::Decrypt => tt_decrypt(&data)?,
            Operation::EncryptGzip => match key_stream {
                Some(key_stream) => tt_encrypt_gzip_with_key_stream(&data, &key_stream)?,
                None => tt_encrypt_gzip(&data)?,
            },
            Operation::DecryptGzip => tt_decrypt_gzip(&data)?,
        };
        Ok(TtEncryptOutput {
            data_base64: general_purpose::STANDARD.encode(output),
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        name: String,
        input_base64: String,
        key_stream_base64: String,
        output_base64: String,
    }

    fn vectors() -> Vec<Vector> {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/vectors.json")).unwrap();
        serde_json::from_value(fixtures["ttEncrypt"].clone()).unwrap()
    }

    #[test]
    fn native_vectors_match_byte_for_byte() {
        for vector in vectors() {
            let input = general_purpose::STANDARD
                .decode(vector.input_base64)
                .unwrap();
            let key_stream: [u8; KEY_STREAM_LEN] = general_purpose::STANDARD
                .decode(vector.key_stream_base64)
                .unwrap()
                .try_into()
                .unwrap();
            let expected = general_purpose::STANDARD
                .decode(vector.output_base64)
                .unwrap();
            let encrypted = tt_encrypt_with_key_stream(&input, &key_stream).unwrap();
            assert_eq!(encrypted, expected, "encryption mismatch: {}", vector.name);
            assert_eq!(
                tt_decrypt(&expected).unwrap(),
                input,
                "decrypt mismatch: {}",
                vector.name
            );
        }
    }

    #[test]
    fn random_and_gzip_round_trips_preserve_content() {
        let input = b"device registration payload";
        let encrypted = tt_encrypt_gzip(input).unwrap();
        assert_eq!(tt_decrypt_gzip(&encrypted).unwrap(), input);
        let raw = tt_encrypt(input).unwrap();
        assert_eq!(tt_decrypt(&raw).unwrap(), input);
    }

    #[test]
    fn invalid_inputs_fail_fast() {
        assert!(tt_encrypt(&[]).is_err());
        assert!(tt_decrypt(b"not an encrypted payload").is_err());
        let mut vector = general_purpose::STANDARD
            .decode(&vectors().remove(0).output_base64)
            .unwrap();
        *vector.last_mut().unwrap() ^= 1;
        assert!(tt_decrypt(&vector).is_err());
    }
}
