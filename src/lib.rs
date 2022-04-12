use lazy_static::lazy_static;

extern crate wapc_guest as guest;
use guest::prelude::*;

use k8s_openapi::api::core::v1 as apicore;

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

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    info!(LOG_DRAIN, "starting validation");

    match serde_json::from_value::<apicore::Pod>(validation_request.request.object.clone()) {
        Ok(pod) => {
            let pod_name = pod.metadata.name.clone();
            let container_images = get_all_container_images(pod);
            let mut policy_verification_errors = vec![];

            for container_image in container_images.iter() {
                for signature in validation_request.settings.signatures.iter() {
                    match signature {
                        Signature::PubKeys(s) => {
                            // just verify if the name matches the image name provided
                            if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                                if let Err(e) = verify_pub_keys_image(
                                    container_image.as_str(),
                                    s.pub_keys.clone(),
                                    s.annotations.clone(),
                                ) {
                                    policy_verification_errors.push(format!(
                                        "verification of image {} failed: {}",
                                        container_image, e
                                    ));
                                }
                            }
                        }
                        Signature::Keyless(s) => {
                            // just verify if the name matches the image name provided
                            if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                                if let Err(e) = verify_keyless_exact_match(
                                    container_image.as_str(),
                                    s.keyless.clone(),
                                    s.annotations.clone(),
                                ) {
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

            if policy_verification_errors.is_empty() {
                kubewarden::accept_request()
            } else {
                kubewarden::reject_request(
                    Some(format!(
                        "pod {:?} is not accepted: {}",
                        pod_name.unwrap_or_default(),
                        policy_verification_errors.join(", ")
                    )),
                    None,
                )
            }
        }
        Err(_) => {
            // We were forwarded a request we cannot unmarshal or
            // understand, just accept it
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn get_all_container_images(pod: apicore::Pod) -> Vec<String> {
    let mut vec: Vec<String> = Vec::new();
    if let Some(spec) = pod.spec {
        vec.append(
            &mut spec
                .containers
                .into_iter()
                .filter_map(|x| x.image)
                .collect(),
        );
        if let Some(init_containers) = spec.init_containers {
            vec.append(
                &mut init_containers
                    .into_iter()
                    .filter_map(|x| x.image)
                    .collect(),
            );
        }
        if let Some(ephemeral_containers) = spec.ephemeral_containers {
            vec.append(
                &mut ephemeral_containers
                    .into_iter()
                    .filter_map(|x| x.image)
                    .collect(),
            );
        }
    }
    vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{Keyless, PubKeys};
    use anyhow::anyhow;
    use k8s_openapi::api::core::v1::{Container, EphemeralContainer, PodSpec};
    use kubewarden::host_capabilities::verification::KeylessInfo;
    use kubewarden::test::Testcase;
    use mockall::automock;
    use serial_test::serial;

    #[automock()]
    pub mod sdk {
        use anyhow::Result;
        use kubewarden::host_capabilities::verification::KeylessInfo;
        use std::collections::HashMap;

        // needed for creating mocks
        #[allow(dead_code)]
        pub fn verify_pub_keys_image(
            _image: &str,
            _pub_keys: Vec<String>,
            _annotations: Option<HashMap<String, String>>,
        ) -> Result<bool> {
            Ok(true)
        }

        // needed for creating mocks
        #[allow(dead_code)]
        pub fn verify_keyless_exact_match(
            _image: &str,
            _keyless: Vec<KeylessInfo>,
            _annotations: Option<HashMap<String, String>>,
        ) -> Result<bool> {
            Ok(true)
        }
    }

    // these tests need to run sequentially because mockall creates a global context to create the mocks
    #[test]
    #[serial]
    fn pub_keys_validation_pass() {
        let ctx = mock_sdk::verify_pub_keys_image_context();
        ctx.expect().times(1).returning(|_, _, _| Ok(true));

        let settings: Settings = Settings {
            signatures: vec![Signature::PubKeys {
                0: PubKeys {
                    image: "nginx".to_string(),
                    pub_keys: vec!["key".to_string()],
                    annotations: None,
                },
            }],
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the nginx container"),
            fixture_file: String::from("test_data/pod_creation.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true)
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
    fn keyless_validation_pass() {
        let ctx = mock_sdk::verify_keyless_exact_match_context();
        ctx.expect().times(2).returning(|_, _, _| Ok(true));

        let settings: Settings = Settings {
            signatures: vec![Signature::Keyless(Keyless {
                image: "nginx".to_string(),
                keyless: vec![KeylessInfo {
                    issuer: "issuer".to_string(),
                    subject: "subject".to_string(),
                }],
                annotations: None,
            })],
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the nginx container"),
            fixture_file: String::from("test_data/pod_creation_with_init_container.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true)
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
                image: "nginx".to_string(),
                keyless: vec![],
                annotations: None,
            })],
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

    use rstest::rstest;

    #[rstest]
    #[case(
    pod(vec![container("nginx")], None, None),
    vec!["nginx".to_string()]
    )]
    #[case(
    pod(vec![container("nginx"), container("alpine")], None, None),
    vec!["nginx".to_string(), "alpine".to_string()]
    )]
    #[case(
    pod(vec![container("nginx")], Some(vec![container("init_container")]), None),
    vec!["nginx".to_string(), "init_container".to_string()]
    )]
    #[case(
    pod(vec![container("nginx")], Some(vec![container("init_container")]), Some(vec![ephemeral_container("ephemeral_container")])),
    vec!["nginx".to_string(), "init_container".to_string() , "ephemeral_container".to_string()]
    )]
    fn test_get_pod_container_images(#[case] pod: apicore::Pod, #[case] expected: Vec<String>) {
        assert_eq!(get_all_container_images(pod), expected)
    }

    fn pod(
        containers: Vec<Container>,
        init_containers: Option<Vec<Container>>,
        ephemeral_containers: Option<Vec<EphemeralContainer>>,
    ) -> apicore::Pod {
        apicore::Pod {
            metadata: Default::default(),
            spec: Some(PodSpec {
                containers,
                ephemeral_containers,
                init_containers,
                ..PodSpec::default()
            }),
            status: None,
        }
    }

    fn container(image: &str) -> Container {
        Container {
            image: Some(image.to_string()),
            ..Container::default()
        }
    }

    fn ephemeral_container(image: &str) -> EphemeralContainer {
        EphemeralContainer {
            image: Some(image.to_string()),
            ..EphemeralContainer::default()
        }
    }
}
