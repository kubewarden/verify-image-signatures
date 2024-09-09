use crate::LOG_DRAIN;

use serde::{Deserialize, Serialize};
use slog::info;
use std::fmt;
use validator::Validate;

mod validation_helpers;

mod pub_keys;
pub(crate) use pub_keys::PubKeys;

mod keyless;
pub(crate) use keyless::Keyless;

pub(crate) mod github_actions;
pub(crate) use github_actions::GithubActions;

mod certificate;
pub(crate) use certificate::Certificate;

mod keyless_prefix;
pub(crate) use keyless_prefix::KeylessPrefix;

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
#[serde(untagged, rename_all = "camelCase")]
pub(crate) enum Signature {
    PubKeys(PubKeys),
    Keyless(Keyless),
    GithubActions(GithubActions),
    KeylessPrefix(KeylessPrefix),
    Certificate(Certificate),
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detailed_display = match self {
            Signature::PubKeys(pub_keys) => pub_keys.to_string(),
            Signature::Keyless(keyless) => keyless.to_string(),
            Signature::GithubActions(github_action) => github_action.to_string(),
            Signature::KeylessPrefix(keyless_prefix) => keyless_prefix.to_string(),
            Signature::Certificate(cert) => cert.to_string(),
        };

        write!(f, "{}", detailed_display)
    }
}

impl Signature {
    pub fn image(&self) -> &str {
        match self {
            Signature::PubKeys(s) => s.image.as_str(),
            Signature::Keyless(s) => s.image.as_str(),
            Signature::GithubActions(s) => s.image.as_str(),
            Signature::KeylessPrefix(s) => s.image.as_str(),
            Signature::Certificate(s) => s.image.as_str(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        match self {
            Signature::PubKeys(pub_keys) => pub_keys.validate().map_err(|e| e.to_string()),
            Signature::Keyless(keyless) => keyless.validate().map_err(|e| e.to_string()),
            Signature::GithubActions(github_actions) => {
                github_actions.validate().map_err(|e| e.to_string())
            }
            Signature::KeylessPrefix(keyless_prefix) => {
                keyless_prefix.validate().map_err(|e| e.to_string())
            }
            Signature::Certificate(cert) => cert.validate(),
        }
    }
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");

        if self.signatures.is_empty() {
            return Err("Signatures must not be empty".to_string());
        }

        let validation_errors: Vec<String> = self
            .signatures
            .iter()
            .filter_map(|s| match s.validate() {
                Ok(_) => None,
                Err(e) => Some(format!("{}: {:?}", s, e)),
            })
            .collect();

        if validation_errors.is_empty() {
            Ok(())
        } else {
            Err(validation_errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mock_crypto_sdk;

    use kubewarden::host_capabilities::crypto::BoolWithReason;
    use kubewarden::host_capabilities::verification::KeylessInfo;
    use kubewarden_policy_sdk::settings::Validatable;
    use serial_test::serial;

    #[test]
    #[serial]
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
    #[serial]
    fn validate_settings_empty_signatures() -> Result<(), ()> {
        let ctx = mock_crypto_sdk::verify_cert_context();
        ctx.expect()
            .times(0)
            .returning(|_cert, _cert_chain, _not_after| Ok(BoolWithReason::True));

        let settings = Settings {
            signatures: vec![],
            modify_images_with_digest: true,
        };

        assert!(settings.validate().is_err());
        Ok(())
    }

    #[test]
    #[serial]
    fn validate_settings_invalid_cert() -> Result<(), ()> {
        let ctx = mock_crypto_sdk::verify_cert_context();
        ctx.expect()
            .times(1)
            .returning(|_cert, _cert_chain, _not_after| {
                Ok(BoolWithReason::False("not a valid cert".to_string()))
            });

        let settings = Settings {
            signatures: vec![Signature::Certificate(Certificate {
                image: "myimage".to_string(),
                certificates: vec!["this is not a PEM cert".to_string()],
                certificate_chain: None,
                require_rekor_bundle: false,
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        let result = settings.validate();
        assert!(result.is_err());
        assert_eq!(
            "Certificate signature for image myimage: \"not a valid cert\"",
            result.unwrap_err()
        );
        Ok(())
    }
}
