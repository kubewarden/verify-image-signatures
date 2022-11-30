use crate::LOG_DRAIN;
use kubewarden::host_capabilities::crypto::{
    verify_cert, Certificate as SDKCert, CertificateEncoding,
};
use kubewarden::host_capabilities::verification::{KeylessInfo, KeylessPrefixInfo};
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
#[serde(untagged, rename_all = "camelCase")]
pub(crate) enum Signature {
    PubKeys(PubKeys),
    Keyless(Keyless),
    GithubActions(GithubActions),
    KeylessPrefix(KeylessPrefix),
    Certificate(Certificate),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PubKeys {
    pub(crate) image: String,
    pub(crate) pub_keys: Vec<String>,
    pub(crate) annotations: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Keyless {
    pub(crate) image: String,
    pub(crate) keyless: Vec<KeylessInfo>,
    pub(crate) annotations: Option<HashMap<String, String>>,
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Certificate {
    /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
    pub(crate) image: String,
    /// PEM encoded certificate used to verify the signature
    pub(crate) certificate: String,
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

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");

        if self.signatures.is_empty() {
            return Err("Signatures must not be empty".to_string());
        }

        // when a certificate is being used, ensure it can be trusted
        for signature in self.signatures.iter() {
            if let Signature::Certificate(s) = signature {
                // build sdk structs:
                let cert = SDKCert {
                    encoding: CertificateEncoding::Pem,
                    data: s.certificate.clone().into_bytes(),
                };
                let cert_chain_opt: Option<Vec<SDKCert>> = match &s.certificate_chain {
                    Some(chain_vec) => {
                        // build vec of sdk certs:
                        let mut chain_sdk: Vec<SDKCert> = vec![];
                        chain_vec.iter().for_each(|d| {
                            chain_sdk.push(SDKCert {
                                encoding: CertificateEncoding::Pem,
                                data: d.clone().into_bytes(),
                            });
                        });
                        Some(chain_sdk)
                    }
                    None => None,
                };
                    Ok(verified) => {
                        if !verified {
                            return Err(format!(
                                "Signatures for image {:?}: Certificate not trusted",
                                s.image
                            ));
                match verify_cert(cert, cert_chain_opt, None) {
                        }
                    }
                    Err(e) => {
                        return Err(format!(
                            "Signatures for image {:?}: Certificate not trusted: {:?}",
                            s.image,
                            e.to_string()
                        ))
                    }
                };
            }
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
