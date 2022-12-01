use kubewarden::host_capabilities::crypto::{
    BoolWithReason, Certificate as SDKCert, CertificateEncoding,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

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
