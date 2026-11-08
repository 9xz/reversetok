use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{
    argus::decrypt_argus,
    crypto::{dyn_encode, md5_bytes},
    error::{Error, Result},
    persona::DynTail,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicFields {
    pub dyn_seed: String,
    pub dyn_version: u32,
    pub seed_state: u64,
    pub nonce: u32,
    pub now_seconds: u64,
    pub f26_tail: Vec<DynTail>,
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

struct ProtoReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> ProtoReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = *self
                .input
                .get(self.offset)
                .ok_or_else(|| Error::InvalidArgument("truncated protobuf varint".into()))?;
            self.offset += 1;
            if index == 9 && byte > 1 {
                return Err(Error::InvalidArgument("protobuf varint overflow".into()));
            }
            value |= ((byte & 0x7f) as u64) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::InvalidArgument("protobuf varint is too long".into()))
    }

    fn next(&mut self) -> Result<Option<(u32, Value<'a>)>> {
        if self.offset == self.input.len() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let field = tag >> 3;
        match tag & 7 {
            0 => Ok(Some((field as u32, Value::Varint(self.varint()?)))),
            2 => {
                let length = usize::try_from(self.varint()?)
                    .map_err(|_| Error::InvalidArgument("protobuf field is too large".into()))?;
                let end = self.offset.checked_add(length).ok_or_else(|| {
                    Error::InvalidArgument("protobuf field length overflow".into())
                })?;
                let bytes = self
                    .input
                    .get(self.offset..end)
                    .ok_or_else(|| Error::InvalidArgument("truncated protobuf bytes".into()))?;
                self.offset = end;
                Ok(Some((field as u32, Value::Bytes(bytes))))
            }
            wire => Err(Error::InvalidArgument(format!(
                "unsupported protobuf wire type {wire}"
            ))),
        }
    }
}

pub fn extract_dynamic_fields(argus: &str, query: &str, body_stub: &[u8]) -> Result<DynamicFields> {
    let parts = decrypt_argus(argus)?;
    let mut reader = ProtoReader::new(&parts.protobuf);
    let mut dyn_seed = None;
    let mut seed_state = None;
    let mut nonce = None;
    let mut now_seconds = None;
    let mut entries = Vec::new();
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (3, Value::Varint(value)) => nonce = Some(value >> 1),
            (12, Value::Varint(value)) => now_seconds = Some(value >> 1),
            (24, Value::Bytes(value)) => {
                dyn_seed = Some(String::from_utf8(value.to_vec()).map_err(|error| {
                    Error::InvalidArgument(format!("dynamic seed is not UTF-8: {error}"))
                })?);
            }
            (25, Value::Varint(value)) => seed_state = Some(value >> 1),
            (26, Value::Bytes(value)) => {
                let mut nested = ProtoReader::new(value);
                let mut algorithm = None;
                let mut output = None;
                while let Some((nested_field, nested_value)) = nested.next()? {
                    match (nested_field, nested_value) {
                        (1, Value::Varint(value)) => algorithm = Some(value >> 1),
                        (2, Value::Bytes(value)) => output = Some(value),
                        _ => {}
                    }
                }
                let algorithm = algorithm.ok_or_else(|| {
                    Error::InvalidArgument("dynamic entry is missing its algorithm".into())
                })?;
                let output = output.ok_or_else(|| {
                    Error::InvalidArgument("dynamic entry is missing its output".into())
                })?;
                entries.push((algorithm, output));
            }
            _ => {}
        }
    }

    let dyn_seed =
        dyn_seed.ok_or_else(|| Error::InvalidArgument("Argus has no dynamic seed field".into()))?;
    let nonce = nonce.ok_or_else(|| Error::InvalidArgument("Argus has no nonce".into()))?;
    let nonce = u32::try_from(nonce)
        .map_err(|_| Error::InvalidArgument("dynamic nonce is out of range".into()))?;
    let now_seconds =
        now_seconds.ok_or_else(|| Error::InvalidArgument("Argus has no timestamp".into()))?;
    let seed_state = seed_state
        .ok_or_else(|| Error::InvalidArgument("Argus has no dynamic seed state".into()))?;
    let mut builtin = None;
    for (index, (algorithm, output)) in entries.iter().enumerate() {
        let version = u32::try_from(*algorithm)
            .map_err(|_| Error::InvalidArgument("dynamic version is out of range".into()))?;
        if let Ok(expected) = dyn_encode(version, query.as_bytes(), body_stub, nonce) {
            if *output == expected {
                builtin = Some((index, version));
                break;
            }
        }
    }
    let (builtin_index, dyn_version) = builtin.ok_or_else(|| {
        Error::InvalidArgument("built-in dynamic entry does not match the request".into())
    })?;
    Ok(DynamicFields {
        dyn_seed,
        dyn_version,
        seed_state,
        nonce,
        now_seconds,
        f26_tail: entries
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != builtin_index)
            .map(|(_, (algorithm, output))| DynTail {
                algorithm: (*algorithm) as u32,
                output_hex: hex::encode(output),
            })
            .collect(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynamicInput {
    argus: String,
    url: String,
    #[serde(default)]
    body_base64: String,
}

pub fn dynamic_json(json: &str) -> String {
    crate::json::respond((|| {
        let input: DynamicInput = serde_json::from_str(json)?;
        let body = if input.body_base64.is_empty() {
            Vec::new()
        } else {
            general_purpose::STANDARD.decode(input.body_base64)?
        };
        let query = url::Url::parse(&input.url)?
            .query()
            .unwrap_or("")
            .to_string();
        extract_dynamic_fields(&input.argus, &query, &md5_bytes(&body))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        argus::{build_protobuf, default_header, default_trailer, encrypt_argus, key4_from_rnd4},
        persona::Persona,
    };

    fn native_dynamic_token(query: &str) -> String {
        let persona = Persona {
            device_id: "1".into(),
            install_id: "2".into(),
            dyn_seed: Some(general_purpose::STANDARD.encode([7u8; 16])),
            dyn_version: Some(6),
            seed_state: Some(3),
            f26_tail: Some(vec![
                DynTail {
                    algorithm: 229,
                    output_hex: "deadbeef".into(),
                },
                DynTail {
                    algorithm: 547,
                    output_hex: "01020304".into(),
                },
            ]),
            ..Persona::default()
        };
        let protobuf =
            build_protobuf(&persona, query, &md5_bytes(b"probe"), 1_700_000_000, 7).unwrap();
        let rnd4 = [1, 2, 3, 4];
        encrypt_argus(
            &protobuf,
            &default_header(),
            &key4_from_rnd4(&rnd4),
            &rnd4,
            &default_trailer(),
        )
    }

    #[test]
    fn extracts_and_validates_dynamic_task_entries() {
        let query = "aid=1233&probe=dynamic";
        let token = native_dynamic_token(query);
        let fields = extract_dynamic_fields(&token, query, &md5_bytes(b"probe")).unwrap();
        assert_eq!(fields.dyn_version, 6);
        assert_eq!(fields.seed_state, 3);
        assert_eq!(fields.nonce, 7);
        assert_eq!(fields.now_seconds, 1_700_000_000);
        assert_eq!(fields.f26_tail.len(), 2);
        assert_eq!(fields.f26_tail[0].algorithm, 229);
        assert_eq!(fields.f26_tail[0].output_hex, "deadbeef");
        assert_eq!(fields.f26_tail[1].algorithm, 547);
    }

    #[test]
    fn rejects_dynamic_entries_from_another_request() {
        let token = native_dynamic_token("aid=1233&probe=dynamic");
        assert!(
            extract_dynamic_fields(&token, "aid=1233&probe=other", &md5_bytes(b"probe")).is_err()
        );
    }
}
