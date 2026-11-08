use std::collections::BTreeMap;

use base64::{engine::general_purpose, Engine as _};
use http::{HeaderName, HeaderValue, Method, Uri};
use serde::{Deserialize, Serialize};

use crate::{
    argus::{build_protobuf, default_header, default_trailer, encrypt_argus, key4_from_rnd4},
    crypto::{gorgon, ladon, md5_bytes, md5_hex},
    error::{Error, Result},
    persona::Persona,
};

#[derive(Clone, Debug, Default)]
pub struct SigningOptions {
    pub now_seconds: Option<u64>,
    pub nonce: Option<u32>,
    pub rnd4: Option<[u8; 4]>,
    pub ladon_random4: Option<[u8; 4]>,
    pub header: Option<[u8; 9]>,
    pub trailer: Option<[u8; 13]>,
    pub key4: Option<[u8; 4]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInput {
    pub persona: Persona,
    #[serde(default = "default_method")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body_base64: String,
    pub now_seconds: Option<u64>,
    pub nonce: Option<u32>,
    pub rnd4_hex: Option<String>,
    pub ladon_random4_hex: Option<String>,
    pub header_hex: Option<String>,
    pub trailer_hex: Option<String>,
    pub key4_hex: Option<String>,
}

fn default_method() -> String {
    "GET".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignOutput {
    pub headers: BTreeMap<String, String>,
    pub method: String,
    pub url: String,
    pub body_base64: String,
}

#[derive(Clone, Debug)]
pub struct MetaSecSigner {
    persona: Persona,
}

pub fn argus_query(url: &str, extra_headers: &BTreeMap<String, String>) -> Result<String> {
    let parsed = url::Url::parse(url)?;
    let query = parsed.query().unwrap_or("");
    let common_params = extra_headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("x-common-params-v2")
                .then_some(value.as_str())
        })
        .unwrap_or("");
    Ok(format!("{query}{common_params}"))
}

impl MetaSecSigner {
    pub fn new(persona: Persona) -> Result<Self> {
        persona.validate()?;
        Ok(Self { persona })
    }

    pub fn persona(&self) -> &Persona {
        &self.persona
    }

    pub fn sign_headers(
        &self,
        url: &str,
        extra_headers: &BTreeMap<String, String>,
        body: &[u8],
        options: &SigningOptions,
    ) -> Result<BTreeMap<String, String>> {
        let argus_query = argus_query(url, extra_headers)?;
        let query = url::Url::parse(url)?.query().unwrap_or("").to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let khronos = options.now_seconds.unwrap_or(now.as_secs());
        let request_ticket = options
            .now_seconds
            .map_or(now.as_millis(), |seconds| u128::from(seconds) * 1000);
        let nonce = options
            .nonce
            .unwrap_or_else(|| rand::random::<u32>() & 0x7fff_ffff);
        let rnd4 = options.rnd4.unwrap_or_else(rand::random::<[u8; 4]>);
        let key4 = options.key4.unwrap_or_else(|| key4_from_rnd4(&rnd4));
        let body_stub = md5_bytes(body);
        let protobuf = build_protobuf(&self.persona, &argus_query, &body_stub, khronos, nonce)?;
        let argus = encrypt_argus(
            &protobuf,
            &options.header.unwrap_or_else(default_header),
            &key4,
            &rnd4,
            &options.trailer.unwrap_or_else(default_trailer),
        );
        let gorgon = gorgon(&query, khronos, Some(&body_stub));
        let ladon_random4 = options
            .ladon_random4
            .unwrap_or_else(rand::random::<[u8; 4]>);
        let aid = self
            .persona
            .app_id
            .parse::<u64>()
            .map_err(|e| Error::InvalidArgument(format!("app_id must be numeric: {e}")))?;
        let ladon = ladon(khronos, self.persona.license_id, aid, ladon_random4);
        let stub_hex = md5_hex(body).to_uppercase();

        Ok(BTreeMap::from([
            ("X-Argus".into(), argus),
            ("X-Gorgon".into(), gorgon),
            ("X-Khronos".into(), khronos.to_string()),
            ("X-Ss-Req-Ticket".into(), request_ticket.to_string()),
            ("X-Ladon".into(), ladon),
            ("X-Ss-Stub".into(), stub_hex),
        ]))
    }

    pub fn sign_request(
        &self,
        request: &mut wreq::Request,
        body: &[u8],
        common_params: Option<&str>,
    ) -> Result<()> {
        self.sign_request_with_options(request, body, common_params, &SigningOptions::default())
    }

    pub fn sign_request_with_options(
        &self,
        request: &mut wreq::Request,
        body: &[u8],
        common_params: Option<&str>,
        options: &SigningOptions,
    ) -> Result<()> {
        let mut headers = BTreeMap::new();
        if let Some(params) = common_params {
            headers.insert("x-common-params-v2".into(), params.into());
        }
        let signed = self.sign_headers(&request.uri().to_string(), &headers, body, options)?;
        for (name, value) in signed {
            let header_name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|e| Error::Wreq(e.to_string()))?;
            let header_value =
                HeaderValue::from_str(&value).map_err(|e| Error::Wreq(e.to_string()))?;
            request.headers_mut().insert(header_name, header_value);
        }
        Ok(())
    }

    pub fn build_request(
        &self,
        method: Method,
        url: &str,
        body: Vec<u8>,
        common_params: Option<&str>,
    ) -> Result<wreq::Request> {
        self.build_request_with_options(
            method,
            url,
            body,
            common_params,
            &SigningOptions::default(),
        )
    }

    pub fn build_request_with_options(
        &self,
        method: Method,
        url: &str,
        body: Vec<u8>,
        common_params: Option<&str>,
        options: &SigningOptions,
    ) -> Result<wreq::Request> {
        let uri: Uri = url
            .parse()
            .map_err(|e| Error::Wreq(format!("invalid URI: {e}")))?;
        let mut request = wreq::Request::new(method, uri);
        self.sign_request_with_options(&mut request, &body, common_params, options)?;
        if !body.is_empty() {
            *request.body_mut() = Some(body.into());
        }
        Ok(request)
    }
}

pub fn sign_input(input: SignInput) -> Result<SignOutput> {
    let body = if input.body_base64.is_empty() {
        Vec::new()
    } else {
        general_purpose::STANDARD.decode(&input.body_base64)?
    };
    let options = SigningOptions {
        now_seconds: input.now_seconds,
        nonce: input.nonce,
        rnd4: match input.rnd4_hex {
            Some(value) => Some(
                hex::decode(value)?
                    .try_into()
                    .map_err(|_| Error::InvalidArgument("rnd4 must be 4 bytes".into()))?,
            ),
            None => None,
        },
        ladon_random4: match input.ladon_random4_hex {
            Some(value) => Some(
                hex::decode(value)?
                    .try_into()
                    .map_err(|_| Error::InvalidArgument("ladon_random4 must be 4 bytes".into()))?,
            ),
            None => None,
        },
        header: match input.header_hex {
            Some(value) => Some(
                hex::decode(value)?
                    .try_into()
                    .map_err(|_| Error::InvalidArgument("header must be 9 bytes".into()))?,
            ),
            None => None,
        },
        trailer: match input.trailer_hex {
            Some(value) => Some(
                hex::decode(value)?
                    .try_into()
                    .map_err(|_| Error::InvalidArgument("trailer must be 13 bytes".into()))?,
            ),
            None => None,
        },
        key4: match input.key4_hex {
            Some(value) => Some(
                hex::decode(value)?
                    .try_into()
                    .map_err(|_| Error::InvalidArgument("key4 must be 4 bytes".into()))?,
            ),
            None => None,
        },
    };
    let signer = MetaSecSigner::new(input.persona)?;
    let method = Method::from_bytes(input.method.as_bytes())
        .map_err(|e| Error::Wreq(format!("invalid HTTP method: {e}")))?;
    let common_params = input.headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("x-common-params-v2")
            .then_some(value.clone())
    });
    let request = signer.build_request_with_options(
        method,
        &input.url,
        body,
        common_params.as_deref(),
        &options,
    )?;
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            let canonical = match name.as_str() {
                "x-argus" => "X-Argus",
                "x-gorgon" => "X-Gorgon",
                "x-khronos" => "X-Khronos",
                "x-ss-req-ticket" => "X-Ss-Req-Ticket",
                "x-ladon" => "X-Ladon",
                "x-ss-stub" => "X-Ss-Stub",
                other => other,
            };
            value
                .to_str()
                .map(|text| (canonical.to_string(), text.to_string()))
                .map_err(|e| Error::Wreq(e.to_string()))
        })
        .collect::<Result<BTreeMap<String, String>>>()?;
    Ok(SignOutput {
        headers,
        method: input.method,
        url: input.url,
        body_base64: input.body_base64,
    })
}

pub fn sign_json(json: &str) -> String {
    crate::json::respond((|| {
        let input = serde_json::from_str::<SignInput>(json)?;
        sign_input(input)
    })())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;
    use crate::argus::decrypt_argus;

    fn native_persona() -> Persona {
        Persona {
            device_id: "0000000000000000001".into(),
            install_id: "0000000000000000002".into(),
            app_version: "47.7.2".into(),
            version_code: "2024707020".into(),
            model: "Pixel 7".into(),
            device: "panther".into(),
            build: "TQ3A.230805.001".into(),
            release: "13".into(),
            security_patch: "2023-08-05".into(),
            fingerprint: "google/panther/panther:13/TQ3A.230805.001/10216780:user/release-keys"
                .into(),
            f23_field2: 18,
            f23_field4: 283_211_776,
            f23_field5: 27_262_976,
            f34: Some("9066089097591521280".into()),
            f35: Some("13838013542538480364".into()),
            f36: Some("7678332264662476164".into()),
            ..Persona::default()
        }
    }

    #[test]
    fn native_protobuf_matches_byte_for_byte() {
        let token = "8fvvl9FBuceE7A90navMO3zbvgpdoPlLe3ZZtV3zgyOpBOwwMQDFsUr14jCIVNprkim047xhrRpUonDwpI8crvW0ZqhfT6whDgUCGoWEBM35DRnfMEcjl7DoFjVb1mI84Plw11wjLGsw5u7oZa15v7U4u18BXRCMCtbuqZ068YME4rYokaoOhbEOoZHBgpfUJW2JI5kYfa7HpJvmKkaeFYN8wFdpigQThzfrEdmJlCA4f5XAYrZ7pMTcUUSsq7xXZrLJ+g5LtOMb/xw6FdsTFZI+C50wSL7RUzUG1gJNN7V7tFlzGrJtZGwuGObd9HCrnLmjuDmPvJIqcXq55QM7F6d4wPdO5CziBnWNbG45mnGpJfrxiKbnYOUwgWoPclhsC/PqXg8PSx7cqYEdTkOYblvepkqooNuxZY7rDYXAjkd/z2/KE6lMuaoVNeiYVCeZb421dI3QwrJAuyybvjj7nt04v8cph+nW+sFQWveAeBypdfNB+gwXSVgUdc/XhPV4W315KLM+dpQBURBxex7fUbYf0Sr7h0niMt1tEi24OsjHlHOq853Unpvrx3YYoEIANdlFiWnm7X3xsaB6FbsIbyA09DAnfbTx/V+2vZbUoAETPz2DzNxmnIXcJDIuD0QZDyrRSQ4TjTjtLJ4QCCiW6XgQkoo8z/KY6nl5fd7VDNBWjThvwPUltvZmdmXxBlh0TIq3dl3DLO+RVc+FjND10z0y";
        let native = decrypt_argus(token).unwrap();
        let persona = native_persona();
        let query = "aid=1233&version_name=47.7.2&probe=vm";
        let stub = hex::decode("d41d8cd98f00b204e9800998ecf8427e").unwrap();
        let built = build_protobuf(&persona, query, &stub, 1_793_934_086, 818_642_162).unwrap();
        assert_eq!(built, native.protobuf);
        assert_eq!(
            encrypt_argus(
                &built,
                &native.header,
                &native.key4,
                &native.rnd4,
                &native.trailer
            ),
            token
        );
    }

    #[test]
    fn custom_display_metadata_enters_protobuf() {
        let persona = Persona {
            device_id: "0000000000000000001".into(),
            install_id: "0000000000000000002".into(),
            resolution: "720x1560".into(),
            dpi: 256,
            ..Persona::default()
        };
        let built = build_protobuf(&persona, "aid=1233", &[0; 16], 1_793_934_086, 7).unwrap();
        let expected = b"\"resolution\":\"720x1560\",\"dpi\":256";
        assert!(built
            .windows(expected.len())
            .any(|window| window == expected));
    }

    #[tokio::test]
    async fn wreq_client_sends_signed_request_to_local_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0u8; 8192];
            let count = stream.read(&mut bytes).unwrap();
            let request = String::from_utf8_lossy(&bytes[..count]).to_ascii_lowercase();
            for header in [
                "x-argus:",
                "x-gorgon:",
                "x-khronos:",
                "x-ss-req-ticket:",
                "x-ladon:",
                "x-ss-stub:",
            ] {
                assert!(request.contains(header), "missing {header} in {request}");
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let persona = Persona {
            device_id: "0000000000000000001".into(),
            install_id: "0000000000000000002".into(),
            ..Persona::default()
        };
        let signer = MetaSecSigner::new(persona).unwrap();
        let request = signer
            .build_request(
                Method::GET,
                &format!("http://{address}/probe?aid=1233"),
                Vec::new(),
                Some("aid=1233"),
            )
            .unwrap();
        let response = wreq::Client::new().execute(request).await.unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
        server.join().unwrap();
    }
}
