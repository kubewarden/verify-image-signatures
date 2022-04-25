use lazy_static::lazy_static;

extern crate wapc_guest as guest;
use guest::prelude::*;

use k8s_openapi::api::core::v1 as apicore;
use k8s_openapi::api::core::v1::{Container, EphemeralContainer, PodSpec};

extern crate kubewarden_policy_sdk as kubewarden;
#[cfg(test)]
use crate::tests::mock_sdk::verify_keyless_exact_match;
#[cfg(test)]
use crate::tests::mock_sdk::verify_pub_keys_image;
#[cfg(not(test))]
use kubewarden::host_capabilities::verification::verify_keyless_exact_match;
#[cfg(not(test))]
use kubewarden::host_capabilities::verification::verify_pub_keys_image;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

use crate::settings::Signature;
use slog::{info, o, warn, Logger};
use wildmatch::WildMatch;

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "sample-policy")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

// Represents an abstraction of an struct that contains an image
// Used to reuse code for Container and EphemeralContainer
trait ImageHolder: Clone {
    fn set_image(&mut self, image: Option<String>);
    fn get_image(&self) -> Option<String>;
}

impl ImageHolder for Container {
    fn set_image(&mut self, image: Option<String>) {
        self.image = image;
    }

    fn get_image(&self) -> Option<String> {
        self.image.clone()
    }
}

impl ImageHolder for EphemeralContainer {
    fn set_image(&mut self, image: Option<String>) {
        self.image = image;
    }

    fn get_image(&self) -> Option<String> {
        self.image.clone()
    }
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    info!(LOG_DRAIN, "starting validation");

    match serde_json::from_value::<apicore::Pod>(validation_request.request.object.clone()) {
        Ok(mut pod) => {
            if let Some(spec) = pod.spec {
                match verify_all_images_in_pod(&spec, &validation_request.settings.signatures) {
                    Ok(spec_with_digest) => {
                        if validation_request.settings.modify_images_with_digest {
                            pod.spec = Some(spec_with_digest);
                            let mutated_object = serde_json::to_value(&pod)?;
                            return kubewarden::mutate_request(mutated_object);
                        } else {
                            return kubewarden::accept_request();
                        }
                    }
                    Err(error) => {
                        return kubewarden::reject_request(
                            Some(format!(
                                "pod {} is not accepted: {}",
                                &pod.metadata.name.unwrap_or_default(),
                                error
                            )),
                            None,
                        );
                    }
                }
            }
            warn!(LOG_DRAIN, "pod without spec, accepting request");
            kubewarden::accept_request()
        }
        Err(_) => {
            // We were forwarded a request we cannot unmarshal or
            // understand, just accept it
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

// verify all images and return a PodSpec with the images replaced with the digest which was used for the verification
fn verify_all_images_in_pod(spec: &PodSpec, signatures: &[Signature]) -> Result<PodSpec, String> {
    let mut policy_verification_errors: Vec<String> = vec![];
    let mut spec_images_with_digest = spec.clone();
    let mut init_containers_with_digest: Option<Vec<Container>> = None;
    let mut ephemeral_containers_with_digest: Option<Vec<EphemeralContainer>> = None;

    let containers_with_digest = verify_container_images(
        &spec.containers,
        &mut policy_verification_errors,
        signatures,
    );
    if let Some(init_containers) = &spec.init_containers {
        init_containers_with_digest = Some(verify_container_images(
            init_containers,
            &mut policy_verification_errors,
            signatures,
        ));
    }
    if let Some(ephemeral_containers) = &spec.ephemeral_containers {
        ephemeral_containers_with_digest = Some(verify_container_images(
            ephemeral_containers,
            &mut policy_verification_errors,
            signatures,
        ));
    }

    if !policy_verification_errors.is_empty() {
        return Err(policy_verification_errors.join(", "));
    }

    spec_images_with_digest.containers = containers_with_digest;
    spec_images_with_digest.init_containers = init_containers_with_digest;
    spec_images_with_digest.ephemeral_containers = ephemeral_containers_with_digest;

    Ok(spec_images_with_digest)
}

// verify images and return containers with the images replaced with the digest which was used for the verification
fn verify_container_images<T>(
    containers: &[T],
    policy_verification_errors: &mut Vec<String>,
    signatures: &[Signature],
) -> Vec<T>
where
    T: ImageHolder,
{
    let mut container_with_images_digests = containers.to_owned();
    for (i, container) in containers.iter().enumerate() {
        let container_image = container.get_image().unwrap();

        for signature in signatures.iter() {
            match signature {
                Signature::PubKeys(s) => {
                    // verify if the name matches the image name provided
                    if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                        match verify_pub_keys_image(
                            container_image.as_str(),
                            s.pub_keys.clone(),
                            s.annotations.clone(),
                        ) {
                            Ok(response) => {
                                let image_with_digest =
                                    [container_image.as_str(), response.digest.as_str()].join("@");
                                container_with_images_digests[i].set_image(Some(image_with_digest));
                            }
                            Err(e) => {
                                policy_verification_errors.push(format!(
                                    "verification of image {} failed: {}",
                                    container_image, e
                                ));
                            }
                        }
                    }
                }
                Signature::Keyless(s) => {
                    // verify if the name matches the image name provided
                    if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                        match verify_keyless_exact_match(
                            container_image.as_str(),
                            s.keyless.clone(),
                            s.annotations.clone(),
                        ) {
                            Ok(response) => {
                                let image_with_digest =
                                    [container_image.as_str(), response.digest.as_str()].join("@");
                                container_with_images_digests[i].set_image(Some(image_with_digest));
                            }
                            Err(e) => {
                                policy_verification_errors.push(format!(
                                    "verification of image {} failed: {}",
                                    container_image, e
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    container_with_images_digests.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{Keyless, PubKeys};
    use anyhow::anyhow;
    use kubewarden::host_capabilities::verification::{KeylessInfo, VerificationResponse};
    use kubewarden::test::Testcase;
    use mockall::automock;
    use serial_test::serial;

    #[automock()]
    pub mod sdk {
        use anyhow::Result;
        use kubewarden::host_capabilities::verification::{KeylessInfo, VerificationResponse};
        use std::collections::HashMap;

        // needed for creating mocks
        #[allow(dead_code)]
        pub fn verify_pub_keys_image(
            _image: &str,
            _pub_keys: Vec<String>,
            _annotations: Option<HashMap<String, String>>,
        ) -> Result<VerificationResponse> {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "mock_digest".to_string(),
            })
        }

        // needed for creating mocks
        #[allow(dead_code)]
        pub fn verify_keyless_exact_match(
            _image: &str,
            _keyless: Vec<KeylessInfo>,
            _annotations: Option<HashMap<String, String>>,
        ) -> Result<VerificationResponse> {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "mock_digest".to_string(),
            })
        }
    }

    // these tests need to run sequentially because mockall creates a global context to create the mocks
    #[test]
    #[serial]
    fn pub_keys_validation_pass_with_mutation() {
        let ctx = mock_sdk::verify_pub_keys_image_context();
        ctx.expect().times(1).returning(|_, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e"
                    .to_string(),
            })
        });

        let settings: Settings = Settings {
            signatures: vec![Signature::PubKeys {
                0: PubKeys {
                    image: "nginx:*".to_string(),
                    pub_keys: vec!["key".to_string()],
                    annotations: None,
                },
            }],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the nginx container"),
            fixture_file: String::from("test_data/pod_creation.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        let expected_mutation: serde_json::Value = serde_json::from_str("{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"nginx\"},\"spec\":{\"containers\":[{\"image\":\"nginx:v1.26@sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e\",\"name\":\"nginx\"}]}}").unwrap();
        assert_eq!(response.mutated_object.unwrap(), expected_mutation);
    }

    #[test]
    #[serial]
    fn pub_keys_validation_pass_with_no_mutation() {
        let ctx = mock_sdk::verify_pub_keys_image_context();
        ctx.expect().times(1).returning(|_, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e"
                    .to_string(),
            })
        });

        let settings: Settings = Settings {
            signatures: vec![Signature::PubKeys {
                0: PubKeys {
                    image: "nginx:*".to_string(),
                    pub_keys: vec!["key".to_string()],
                    annotations: None,
                },
            }],
            modify_images_with_digest: false,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the nginx container"),
            fixture_file: String::from("test_data/pod_creation.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        assert!(response.mutated_object.is_none());
    }

    #[test]
    #[serial]
    fn pub_keys_validation_dont_pass() {
        let ctx = mock_sdk::verify_pub_keys_image_context();
        ctx.expect()
            .times(1)
            .returning(|_, _, _| Err(anyhow!("error")));

        let settings: Settings = Settings {
            signatures: vec![Signature::PubKeys {
                0: PubKeys {
                    image: "*".to_string(),
                    pub_keys: vec!["key".to_string()],
                    annotations: None,
                },
            }],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should fail when validating the nginx container"),
            fixture_file: String::from("test_data/pod_creation.json"),
            settings,
            expected_validation_result: false,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, false);
        assert!(response.mutated_object.is_none());
    }

    #[test]
    #[serial]
    fn keyless_validation_pass_with_mutation() {
        let ctx = mock_sdk::verify_keyless_exact_match_context();
        ctx.expect().times(1).returning(|_, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e"
                    .to_string(),
            })
        });

        let settings: Settings = Settings {
            signatures: vec![Signature::Keyless(Keyless {
                image: "nginx:*".to_string(),
                keyless: vec![KeylessInfo {
                    issuer: "issuer".to_string(),
                    subject: "subject".to_string(),
                }],
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the nginx container"),
            fixture_file: String::from("test_data/pod_creation.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        let expected_mutation: serde_json::Value = serde_json::from_str("{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"nginx\"},\"spec\":{\"containers\":[{\"image\":\"nginx:v1.26@sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e\",\"name\":\"nginx\"}]}}").unwrap();
        assert_eq!(response.mutated_object.unwrap(), expected_mutation);
    }

    #[test]
    #[serial]
    fn keyless_validation_dont_pass() {
        let ctx = mock_sdk::verify_keyless_exact_match_context();
        ctx.expect()
            .times(1)
            .returning(|_, _, _| Err(anyhow!("error")));

        let settings: Settings = Settings {
            signatures: vec![Signature::Keyless(Keyless {
                image: "nginx:*".to_string(),
                keyless: vec![],
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should fail when validating the nginx container"),
            fixture_file: String::from("test_data/pod_creation.json"),
            settings,
            expected_validation_result: false,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, false)
    }

    #[test]
    #[serial]
    fn validation_pass_when_there_is_no_matching_containers() {
        let ctx = mock_sdk::verify_pub_keys_image_context();
        ctx.expect()
            .times(0)
            .returning(|_, _, _| Err(anyhow!("error")));

        let ctx = mock_sdk::verify_keyless_exact_match_context();
        ctx.expect()
            .times(0)
            .returning(|_, _, _| Err(anyhow!("error")));

        let settings: Settings = Settings {
            signatures: vec![
                Signature::PubKeys {
                    0: PubKeys {
                        image: "no_matching".to_string(),
                        pub_keys: vec![],
                        annotations: None,
                    },
                },
                Signature::Keyless(Keyless {
                    image: "no_matching".to_string(),
                    keyless: vec![],
                    annotations: None,
                }),
            ],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should return true since there is no matching containers"),
            fixture_file: String::from("test_data/pod_creation.json"),
            settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true)
    }

    #[test]
    #[serial]
    fn validation_with_multiple_containers_fail_if_one_fails() {
        let ctx_pub_keys = mock_sdk::verify_pub_keys_image_context();
        ctx_pub_keys.expect().times(1).returning(|_, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e"
                    .to_string(),
            })
        });

        let ctx_keyless = mock_sdk::verify_keyless_exact_match_context();
        ctx_keyless
            .expect()
            .times(1)
            .returning(|_, _, _| Err(anyhow!("error")));

        let settings: Settings = Settings {
            signatures: vec![
                Signature::Keyless(Keyless {
                    image: "nginx".to_string(),
                    keyless: vec![KeylessInfo {
                        issuer: "issuer".to_string(),
                        subject: "subject".to_string(),
                    }],
                    annotations: None,
                }),
                Signature::PubKeys {
                    0: PubKeys {
                        image: "init".to_string(),
                        pub_keys: vec![],
                        annotations: None,
                    },
                },
            ],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should fail because one validation fails"),
            fixture_file: String::from("test_data/pod_creation_with_init_container.json"),
            settings,
            expected_validation_result: false,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, false);
        assert!(response.mutated_object.is_none());
    }

    #[test]
    #[serial]
    fn validation_with_multiple_containers_with_mutation_pass() {
        let ctx_pub_keys = mock_sdk::verify_pub_keys_image_context();
        ctx_pub_keys.expect().times(1).returning(|_, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e"
                    .to_string(),
            })
        });

        let ctx_keyless = mock_sdk::verify_keyless_exact_match_context();
        ctx_keyless.expect().times(1).returning(|_, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:a3d850c2022ebf02156114178ef35298d63f83c740e7b5dd7777ff05898880f8"
                    .to_string(),
            })
        });

        let settings: Settings = Settings {
            signatures: vec![
                Signature::Keyless(Keyless {
                    image: "nginx".to_string(),
                    keyless: vec![KeylessInfo {
                        issuer: "issuer".to_string(),
                        subject: "subject".to_string(),
                    }],
                    annotations: None,
                }),
                Signature::PubKeys {
                    0: PubKeys {
                        image: "init".to_string(),
                        pub_keys: vec![],
                        annotations: None,
                    },
                },
            ],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the nginx and init containers"),
            fixture_file: String::from("test_data/pod_creation_with_init_container.json"),
            settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        let expected: serde_json::Value = serde_json::from_str("{\"apiVersion\": \"v1\", \"kind\": \"Pod\", \"metadata\": {\"name\": \"nginx\"}, \"spec\": {\"containers\": [{\"image\": \"nginx@sha256:a3d850c2022ebf02156114178ef35298d63f83c740e7b5dd7777ff05898880f8\", \"name\": \"nginx\"}], \"initContainers\": [{\"image\":\"init@sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e\", \"name\": \"init\"}]}}").unwrap();
        assert_eq!(response.mutated_object.unwrap(), expected);
    }
}
