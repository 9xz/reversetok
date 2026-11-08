use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynTail {
    pub algorithm: u32,
    pub output_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Persona {
    pub device_id: String,
    pub install_id: String,
    pub app_id: String,
    pub license_id: u64,
    pub sdk_version: String,
    pub sdk_version_code: u64,
    pub app_version: String,
    pub version_code: String,
    pub model: String,
    pub device: String,
    pub build: String,
    pub release: String,
    pub security_patch: String,
    pub fingerprint: String,
    pub channel: String,
    pub resolution: String,
    pub dpi: u64,
    pub allow_empty_identity: bool,
    pub device_token: Option<String>,
    pub dyn_seed: Option<String>,
    pub dyn_version: Option<u32>,
    pub seed_state: Option<u64>,
    pub session_blob_hex: Option<String>,
    pub rsk2_ms: u64,
    pub env_salt32: u32,
    pub f23_field2: u64,
    pub f23_field4: u64,
    pub f23_field5: u64,
    pub f26_tail: Option<Vec<DynTail>>,
    pub f34: Option<String>,
    pub f35: Option<String>,
    pub f36: Option<String>,
}

impl Default for Persona {
    fn default() -> Self {
        Self {
            device_id: String::new(),
            install_id: String::new(),
            app_id: "1233".into(),
            license_id: 2_142_840_551,
            sdk_version: "v05.03.04-ov-android".into(),
            sdk_version_code: 0x0503_0420,
            app_version: "47.7.2".into(),
            version_code: "2024707020".into(),
            model: "Pixel 7".into(),
            device: "panther".into(),
            build: "TQ3A.230805.001".into(),
            release: "13".into(),
            security_patch: "2023-08-05".into(),
            fingerprint: "google/panther/panther:13/TQ3A.230805.001/10216780:user/release-keys"
                .into(),
            channel: "googleplay".into(),
            resolution: "1080x2400".into(),
            dpi: 420,
            allow_empty_identity: false,
            device_token: None,
            dyn_seed: None,
            dyn_version: None,
            seed_state: None,
            session_blob_hex: None,
            rsk2_ms: 2,
            env_salt32: 0x4002_0341,
            f23_field2: 18,
            f23_field4: 283_211_776,
            f23_field5: 27_262_976,
            f26_tail: None,
            f34: None,
            f35: None,
            f36: None,
        }
    }
}

impl Persona {
    pub fn validate(&self) -> Result<()> {
        if !self.allow_empty_identity && (self.device_id.is_empty() || self.install_id.is_empty()) {
            return Err(Error::InvalidArgument(
                "device_id and install_id are required".into(),
            ));
        }
        if let Some(seed) = &self.dyn_seed {
            base64::engine::general_purpose::STANDARD.decode(seed)?;
            let version = self.dyn_version.unwrap_or(6);
            if !(1..=6).contains(&version) {
                return Err(Error::UnsupportedDynVersion(version));
            }
        }
        if let Some(blob) = &self.session_blob_hex {
            hex::decode(blob)?;
        }
        Ok(())
    }

    pub fn dyn_version(&self) -> u32 {
        self.dyn_version.unwrap_or(6)
    }

    pub fn seed_state(&self) -> u64 {
        self.seed_state
            .unwrap_or(if self.dyn_seed.is_some() { 3 } else { 1 })
    }
}

pub fn parse_optional_u64(value: &Option<String>) -> Result<Option<u64>> {
    match value {
        None => Ok(None),
        Some(text) => {
            let trimmed = text.trim();
            let parsed = if let Some(hex) = trimmed.strip_prefix("0x") {
                u64::from_str_radix(hex, 16)
            } else {
                trimmed.parse::<u64>()
            };
            parsed
                .map(Some)
                .map_err(|e| Error::InvalidArgument(format!("invalid u64 {trimmed:?}: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_identity_requires_explicit_opt_in() {
        let persona = Persona::default();
        assert!(persona.validate().is_err());
        let registration = Persona {
            allow_empty_identity: true,
            ..Persona::default()
        };
        assert!(registration.validate().is_ok());
    }
}
