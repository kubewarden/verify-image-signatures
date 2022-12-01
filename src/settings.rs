use crate::LOG_DRAIN;
use kubewarden::host_capabilities::crypto::{
    BoolWithReason, Certificate as SDKCert, CertificateEncoding,
};

#[cfg(test)]
use crate::tests::mock_crypto_sdk::verify_cert;

#[cfg(not(test))]
use kubewarden::host_capabilities::crypto::verify_cert;

use kubewarden::host_capabilities::verification::{KeylessInfo, KeylessPrefixInfo};
use std::collections::HashMap;
use std::fmt;

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
    fn validate(&self) -> Result<(), String> {
        match self {
            Signature::PubKeys(_) => Ok(()),
            Signature::Keyless(_) => Ok(()),
            Signature::GithubActions(_) => Ok(()),
            Signature::KeylessPrefix(_) => Ok(()),
            Signature::Certificate(cert) => cert.validate(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PubKeys {
    pub(crate) image: String,
    pub(crate) pub_keys: Vec<String>,
    pub(crate) annotations: Option<HashMap<String, String>>,
}

impl fmt::Display for PubKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pub key signature for image {}", self.image)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Keyless {
    pub(crate) image: String,
    pub(crate) keyless: Vec<KeylessInfo>,
    pub(crate) annotations: Option<HashMap<String, String>>,
}

impl fmt::Display for Keyless {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyless signature for image {}", self.image)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeylessGithubActionsInfo {
    /// owner of the repository. E.g: octocat
    pub(crate) owner: String,
    /// Optional - Repo of the GH Action workflow that signed the artifact. E.g: example-repo
    pub(crate) repo: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GithubActions {
    /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
    pub(crate) image: String,
    /// GitHub Actions information that must be found in the signature
    pub(crate) github_actions: KeylessGithubActionsInfo,
    /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
    pub(crate) annotations: Option<HashMap<String, String>>,
}

impl fmt::Display for GithubActions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitHub action signature for image {}", self.image)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Certificate {
    /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
    pub(crate) image: String,
    /// PEM encoded certificate used to verify the signature
    pub(crate) certificates: Vec<String>,
    /// Optional - the certificate chain that is used to verify the provided
    /// certificate. When not specified, the certificate is assumed to be trusted
    pub(crate) certificate_chain: Option<Vec<String>>,
    /// Require the  signature layer to have a Rekor bundle.
    /// Having a Rekor bundle allows further checks to be performed,
    /// like ensuring the signature has been produced during the validity
    /// time frame of the certificate.
    ///
    /// It is recommended to set this value to `true` to have a more secure
    /// verification process.
    pub(crate) require_rekor_bundle: bool,
    /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
    pub(crate) annotations: Option<HashMap<String, String>>,
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Certificate signature for image {}", self.image)
    }
}
impl Certificate {
    fn validate(&self) -> Result<(), String> {
        if self.certificates.is_empty() {
            return Err("no certificate provided".to_string());
        }

        let cert_chain_opt: Option<Vec<SDKCert>> = self.certificate_chain.as_ref().map({
            |chain| {
                chain
                    .iter()
                    .map(|c| SDKCert {
                        encoding: CertificateEncoding::Pem,
                        data: c.to_owned().into_bytes(),
                    })
                    .collect()
            }
        });

        let validation_errors: Vec<String> = self
            .certificates
            .iter()
            .filter_map(|c| {
                let sdk_cert = SDKCert {
                    encoding: CertificateEncoding::Pem,
                    data: c.to_owned().into_bytes(),
                };
                match verify_cert(sdk_cert, cert_chain_opt.clone(), None) {
                    Ok(b) => match b {
                        BoolWithReason::True => None,
                        BoolWithReason::False(reason) => {
                            Some(format!("Certificate not trusted: {}", reason))
                        }
                    },
                    Err(e) => Some(format!(
                        "Error when verifying certificate: {:?}",
                        e.to_string()
                    )),
                }
            })
            .collect();

        if validation_errors.is_empty() {
            Ok(())
        } else {
            Err(validation_errors.join("; "))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeylessPrefix {
    /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
    pub(crate) image: String,
    /// List of keyless signatures that must be found
    pub(crate) keyless_prefix: Vec<KeylessPrefixInfo>,
    /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
    pub(crate) annotations: Option<HashMap<String, String>>,
}

impl fmt::Display for KeylessPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyless signature for image {}", self.image)
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
            "Certificate signature for image myimage: \"Certificate not trusted: not a valid cert\"",
            result.unwrap_err()
        );
        Ok(())
    }
}
