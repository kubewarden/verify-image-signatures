use kubewarden::host_capabilities::crypto::{
    BoolWithReason, Certificate as SDKCert, CertificateEncoding,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{fmt, str};

use super::validation_helpers::validate_vector_of_pem_strings;

#[cfg(test)]
use crate::tests::mock_crypto_sdk::verify_cert;

#[cfg(not(test))]
use kubewarden::host_capabilities::crypto::verify_cert;

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
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.image.is_empty() {
            return Err("no image provided".to_string());
        }

        if self.certificates.is_empty() {
            return Err("no certificate provided".to_string());
        }

        if let Some(chain) = &self.certificate_chain {
            validate_vector_of_pem_strings(chain).map_err(|e| e.code.to_string())?;
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

#[cfg(test)]
mod tests {
    use super::super::validation_helpers::tests::PEM_DATA;
    use super::*;
    use crate::tests::mock_crypto_sdk;
    use serial_test::serial;

    #[test]
    #[serial]
    fn check_image() {
        let certificate = Certificate {
            image: "".to_string(),
            certificates: vec!["a cert".to_string()],
            certificate_chain: None,
            require_rekor_bundle: true,
            annotations: None,
        };

        let ctx = mock_crypto_sdk::verify_cert_context();
        ctx.expect()
            .times(0)
            .returning(|_cert, _cert_chain, _not_after| Ok(BoolWithReason::True));

        let result = certificate.validate();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string().as_str(),
            "no image provided"
        );
    }

    #[test]
    #[serial]
    fn check_certificate_chain_is_pem() {
        let certificate = Certificate {
            image: "hello".to_string(),
            certificates: vec!["a cert".to_string()],
            certificate_chain: Some(vec!["not pem".to_string()]),
            require_rekor_bundle: true,
            annotations: None,
        };

        let ctx = mock_crypto_sdk::verify_cert_context();
        ctx.expect()
            .times(0)
            .returning(|_cert, _cert_chain, _not_after| Ok(BoolWithReason::True));

        let result = certificate.validate();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string().as_str(),
            "non-PEM data found"
        );
    }

    #[test]
    #[serial]
    fn check_certificate() {
        let certificate = Certificate {
            image: "hello".to_string(),
            certificates: vec!["good1".to_string()],
            certificate_chain: Some(vec![PEM_DATA.to_string()]),
            require_rekor_bundle: true,
            annotations: None,
        };

        let ctx = mock_crypto_sdk::verify_cert_context();
        ctx.expect()
            .times(1)
            .returning(|cert, _cert_chain, _not_after| {
                let cert_data =
                    str::from_utf8(&cert.data).expect("cannot convert cert data to string");
                match cert_data {
                    "good1" | "good2" => Ok(BoolWithReason::True),
                    _ => Ok(BoolWithReason::False("not valid".to_string())),
                }
            });

        let result = certificate.validate();
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn check_multiple_certificates() {
        let certificate = Certificate {
            image: "hello".to_string(),
            certificates: vec!["good1".to_string(), "good2".to_string()],
            certificate_chain: Some(vec![PEM_DATA.to_string()]),
            require_rekor_bundle: true,
            annotations: None,
        };

        let ctx = mock_crypto_sdk::verify_cert_context();
        ctx.expect()
            .times(2)
            .returning(|cert, _cert_chain, _not_after| {
                let cert_data =
                    str::from_utf8(&cert.data).expect("cannot convert cert data to string");
                match cert_data {
                    "good1" | "good2" => Ok(BoolWithReason::True),
                    _ => Ok(BoolWithReason::False("not valid".to_string())),
                }
            });

        let result = certificate.validate();
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn require_all_certs_to_be_valid() {
        let certificate = Certificate {
            image: "hello".to_string(),
            certificates: vec!["good1".to_string(), "bad1".to_string()],
            certificate_chain: Some(vec![PEM_DATA.to_string()]),
            require_rekor_bundle: true,
            annotations: None,
        };

        let ctx = mock_crypto_sdk::verify_cert_context();
        ctx.expect()
            .times(2)
            .returning(|cert, _cert_chain, _not_after| {
                let cert_data =
                    str::from_utf8(&cert.data).expect("cannot convert cert data to string");
                match cert_data {
                    "good1" | "good2" => Ok(BoolWithReason::True),
                    _ => Ok(BoolWithReason::False("not valid".to_string())),
                }
            });

        let result = certificate.validate();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().as_str(),
            "Certificate not trusted: not valid"
        );
    }
}
