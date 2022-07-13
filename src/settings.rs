use crate::LOG_DRAIN;
use kubewarden::host_capabilities::verification::{
    KeylessGithubActionsInfo, KeylessInfo, KeylessPrefixInfo,
};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use slog::info;

fn default_as_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Settings {
    pub(crate) signatures: Vec<Signature>,
    #[serde(default = "default_as_true")]
    pub(crate) modify_images_with_digest: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum Signature {
    PubKeys(PubKeys),
    Keyless(Keyless),
    GithubActions(GithubActions),
    KeylessPrefix(KeylessPrefix),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PubKeys {
    pub(crate) image: String,
    pub(crate) pub_keys: Vec<String>,
    pub(crate) annotations: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Keyless {
    pub(crate) image: String,
    pub(crate) keyless: Vec<KeylessInfo>,
    pub(crate) annotations: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GithubActions {
    /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
    pub(crate) image: String,
    // GitHub Actions information that must be found in the signature
    pub(crate) github_actions: KeylessGithubActionsInfo,
    /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
    pub(crate) annotations: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct KeylessPrefix {
    /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
    pub(crate) image: String,
    /// List of keyless signatures that must be found
    pub(crate) keyless_prefix: Vec<KeylessPrefixInfo>,
    /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
    pub(crate) annotations: Option<HashMap<String, String>>,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");

        if self.signatures.is_empty() {
            return Err("Signatures must not be empty".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_settings_valid() -> Result<(), ()> {
        let settings = Settings {
            signatures: vec![Signature::Keyless(Keyless {
                image: "image".to_string(),
                keyless: vec![KeylessInfo {
                    issuer: "issuer".to_string(),
                    subject: "subject".to_string(),
                }],
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        assert!(settings.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_settings_empty_signatures() -> Result<(), ()> {
        let settings = Settings {
            signatures: vec![],
            modify_images_with_digest: true,
        };

        assert!(settings.validate().is_err());
        Ok(())
    }
}
