use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1 as apicore;
use k8s_openapi::api::core::v1::{Container, EphemeralContainer, PodSpec, ReplicationController};

extern crate kubewarden_policy_sdk as kubewarden;
#[cfg(test)]
use crate::tests::mock_sdk::{
    verify_certificate, verify_keyless_exact_match, verify_keyless_github_actions,
    verify_keyless_prefix_match, verify_pub_keys_image,
};
use anyhow::Result;
use kubewarden::host_capabilities::verification::VerificationResponse;
#[cfg(not(test))]
use kubewarden::host_capabilities::verification::{
    verify_certificate, verify_keyless_exact_match, verify_keyless_github_actions,
    verify_keyless_prefix_match, verify_pub_keys_image,
};
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};
use serde::de::DeserializeOwned;

mod settings;
use settings::Settings;

use crate::settings::Signature;
use slog::{o, warn, Logger};
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

/// Represents all resources that can be validated with this policy
trait ValidatingResource {
    fn name(&self) -> String;
    fn spec(&self) -> Option<PodSpec>;
}

impl ValidatingResource for Deployment {
    fn name(&self) -> String {
        self.metadata.name.clone().unwrap_or_else(|| "".to_string())
    }

    fn spec(&self) -> Option<PodSpec> {
        self.spec.as_ref()?.template.spec.clone()
    }
}

impl ValidatingResource for ReplicaSet {
    fn name(&self) -> String {
        self.metadata.name.clone().unwrap_or_else(|| "".to_string())
    }

    fn spec(&self) -> Option<PodSpec> {
        self.spec.as_ref()?.template.as_ref()?.spec.clone()
    }
}

impl ValidatingResource for StatefulSet {
    fn name(&self) -> String {
        self.metadata.name.clone().unwrap_or_else(|| "".to_string())
    }

    fn spec(&self) -> Option<PodSpec> {
        self.spec.as_ref()?.template.spec.clone()
    }
}

impl ValidatingResource for DaemonSet {
    fn name(&self) -> String {
        self.metadata.name.clone().unwrap_or_else(|| "".to_string())
    }

    fn spec(&self) -> Option<PodSpec> {
        self.spec.as_ref()?.template.spec.clone()
    }
}

impl ValidatingResource for ReplicationController {
    fn name(&self) -> String {
        self.metadata.name.clone().unwrap_or_else(|| "".to_string())
    }

    fn spec(&self) -> Option<PodSpec> {
        self.spec.as_ref()?.template.as_ref()?.spec.clone()
    }
}

impl ValidatingResource for Job {
    fn name(&self) -> String {
        self.metadata.name.clone().unwrap_or_else(|| "".to_string())
    }

    fn spec(&self) -> Option<PodSpec> {
        self.spec.as_ref()?.template.spec.clone()
    }
}

impl ValidatingResource for CronJob {
    fn name(&self) -> String {
        self.metadata.name.clone().unwrap_or_else(|| "".to_string())
    }

    fn spec(&self) -> Option<PodSpec> {
        self.spec
            .as_ref()?
            .job_template
            .spec
            .as_ref()?
            .template
            .spec
            .clone()
    }
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    match validation_request.request.kind.kind.as_str() {
        "Deployment" => validate_resource::<Deployment>(validation_request),
        "ReplicaSet" => validate_resource::<ReplicaSet>(validation_request),
        "StatefulSet" => validate_resource::<StatefulSet>(validation_request),
        "DaemonSet" => validate_resource::<DaemonSet>(validation_request),
        "ReplicationController" => validate_resource::<ReplicationController>(validation_request),
        "Job" => validate_resource::<Job>(validation_request),
        "CronJob" => validate_resource::<CronJob>(validation_request),
        "Pod" => {
            match serde_json::from_value::<apicore::Pod>(validation_request.request.object.clone())
            {
                Ok(mut pod) => {
                    if let Some(spec) = pod.spec {
                        match verify_all_images_in_pod(
                            &spec,
                            &validation_request.settings.signatures,
                        ) {
                            Ok(spec_with_digest) => {
                                if validation_request.settings.modify_images_with_digest
                                    && spec_with_digest.is_some()
                                {
                                    pod.spec = spec_with_digest;
                                    let mutated_object = serde_json::to_value(&pod)?;
                                    return kubewarden::mutate_request(mutated_object);
                                } else {
                                    return kubewarden::accept_request();
                                }
                            }
                            Err(error) => {
                                return kubewarden::reject_request(
                                    Some(format!(
                                        "Pod {} is not accepted: {}",
                                        &pod.metadata.name.unwrap_or_default(),
                                        error
                                    )),
                                    None,
                                    None,
                                    None,
                                );
                            }
                        }
                    }
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
        _ => {
            // We were forwarded a request we cannot unmarshal or
            // understand, just accept it
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

// validate any resource that contains a Pod. e.g. Deployment, StatefulSet, ...
// it does not modify the container with the manifest digest. Mutation just happens at the Pod level
fn validate_resource<T: ValidatingResource + DeserializeOwned>(
    validation_request: ValidationRequest<Settings>,
) -> CallResult {
    match serde_json::from_value::<T>(validation_request.request.object.clone()) {
        Ok(resource) => {
            if let Some(spec) = resource.spec() {
                match verify_all_images_in_pod(&spec, &validation_request.settings.signatures) {
                    Ok(_) => {
                        return kubewarden::accept_request();
                    }
                    Err(error) => {
                        return kubewarden::reject_request(
                            Some(format!(
                                "Resource {} is not accepted: {}",
                                &resource.name(),
                                error
                            )),
                            None,
                            None,
                            None,
                        );
                    }
                }
            }
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
fn verify_all_images_in_pod(
    spec: &PodSpec,
    signatures: &[Signature],
) -> Result<Option<PodSpec>, String> {
    let mut policy_verification_errors: Vec<String> = vec![];
    let mut spec_images_with_digest = spec.clone();
    let mut is_modified_with_digest = false;

    if let Some(containers_with_digest) = verify_container_images(
        &spec.containers,
        &mut policy_verification_errors,
        signatures,
    ) {
        spec_images_with_digest.containers = containers_with_digest;
        is_modified_with_digest = true;
    }
    if let Some(init_containers) = &spec.init_containers {
        if let Some(init_containers_with_digest) =
            verify_container_images(init_containers, &mut policy_verification_errors, signatures)
        {
            spec_images_with_digest.init_containers = Some(init_containers_with_digest);
            is_modified_with_digest = true;
        }
    }
    if let Some(ephemeral_containers) = &spec.ephemeral_containers {
        if let Some(ephemeral_containers_with_digest) = verify_container_images(
            ephemeral_containers,
            &mut policy_verification_errors,
            signatures,
        ) {
            spec_images_with_digest.ephemeral_containers = Some(ephemeral_containers_with_digest);
            is_modified_with_digest = true;
        }
    }

    if !policy_verification_errors.is_empty() {
        return Err(policy_verification_errors.join(", "));
    }

    if is_modified_with_digest {
        Ok(Some(spec_images_with_digest))
    } else {
        Ok(None)
    }
}

// verify images and return containers with the images replaced with the digest which was used for the verification
fn verify_container_images<T>(
    containers: &[T],
    policy_verification_errors: &mut Vec<String>,
    signatures: &[Signature],
) -> Option<Vec<T>>
where
    T: ImageHolder + PartialEq,
{
    let mut container_with_images_digests = containers.to_owned();

    for (i, container) in containers.iter().enumerate() {
        let container_image = container.get_image().unwrap();

        for signature in signatures.iter() {
            match signature {
                Signature::PubKeys(s) => {
                    // verify if the name matches the image name provided
                    if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                        handle_verification_response(
                            verify_pub_keys_image(
                                container_image.as_str(),
                                s.pub_keys.clone(),
                                s.annotations.clone(),
                            ),
                            container_image.as_str(),
                            &mut container_with_images_digests[i],
                            policy_verification_errors,
                        );
                    }
                }
                Signature::Keyless(s) => {
                    // verify if the name matches the image name provided
                    if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                        handle_verification_response(
                            verify_keyless_exact_match(
                                container_image.as_str(),
                                s.keyless.clone(),
                                s.annotations.clone(),
                            ),
                            container_image.as_str(),
                            &mut container_with_images_digests[i],
                            policy_verification_errors,
                        );
                    }
                }
                Signature::KeylessPrefix(s) => {
                    // verify if the name matches the image name provided
                    if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                        handle_verification_response(
                            verify_keyless_prefix_match(
                                container_image.as_str(),
                                s.keyless_prefix.clone(),
                                s.annotations.clone(),
                            ),
                            container_image.as_str(),
                            &mut container_with_images_digests[i],
                            policy_verification_errors,
                        );
                    }
                }
                Signature::GithubActions(s) => {
                    // verify if the name matches the image name provided
                    if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                        handle_verification_response(
                            verify_keyless_github_actions(
                                container_image.as_str(),
                                s.github_actions.owner.clone(),
                                s.github_actions.repo.clone(),
                                s.annotations.clone(),
                            ),
                            container_image.as_str(),
                            &mut container_with_images_digests[i],
                            policy_verification_errors,
                        );
                    }
                }
                Signature::Certificate(s) => {
                    // verify if the name matches the image name provided
                    if WildMatch::new(s.image.as_str()).matches(container_image.as_str()) {
                        handle_verification_response(
                            verify_certificate(
                                container_image.as_str(),
                                s.certificate.clone(),
                                s.certificate_chain.clone(),
                                s.require_rekor_bundle,
                                s.annotations.clone(),
                            ),
                            container_image.as_str(),
                            &mut container_with_images_digests[i],
                            policy_verification_errors,
                        );
                    }
                }
            }
        }
    }

    if containers != container_with_images_digests {
        Some(container_with_images_digests.to_vec())
    } else {
        None
    }
}

fn handle_verification_response<T>(
    response: Result<VerificationResponse>,
    container_image: &str,
    container_with_images_digests: &mut T,
    policy_verification_errors: &mut Vec<String>,
) where
    T: ImageHolder,
{
    match response {
        Ok(response) => add_digest_if_not_present(
            container_image,
            response.digest.as_str(),
            container_with_images_digests,
        ),
        Err(e) => {
            policy_verification_errors.push(format!(
                "verification of image {} failed: {}",
                container_image, e
            ));
        }
    };
}

// returns true if digest was appended
fn add_digest_if_not_present<T>(
    container_image: &str,
    digest: &str,
    container_with_images_digests: &mut T,
) where
    T: ImageHolder,
{
    if !container_image.contains(digest) {
        let image_with_digest = [container_image, digest].join("@");
        container_with_images_digests.set_image(Some(image_with_digest));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{
        Certificate, GithubActions, Keyless, KeylessGithubActionsInfo, KeylessPrefix, PubKeys,
    };
    use anyhow::anyhow;
    use kubewarden::host_capabilities::verification::{
        KeylessInfo, KeylessPrefixInfo, VerificationResponse,
    };
    use kubewarden::test::Testcase;
    use mockall::automock;
    use serde_json::json;
    use serial_test::serial;

    #[automock()]
    pub mod sdk {
        use anyhow::Result;
        use kubewarden::host_capabilities::verification::{
            KeylessInfo, KeylessPrefixInfo, VerificationResponse,
        };
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

        // needed for creating mocks
        #[allow(dead_code)]
        pub fn verify_keyless_prefix_match(
            _image: &str,
            _keyless_prefix: Vec<KeylessPrefixInfo>,
            _annotations: Option<HashMap<String, String>>,
        ) -> Result<VerificationResponse> {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "mock_digest".to_string(),
            })
        }

        // needed for creating mocks
        #[allow(dead_code)]
        pub fn verify_keyless_github_actions(
            _image: &str,
            _owner: String,
            _repo: Option<String>,
            _annotations: Option<HashMap<String, String>>,
        ) -> Result<VerificationResponse> {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "mock_digest".to_string(),
            })
        }

        // needed for creating mocks
        #[allow(dead_code)]
        pub fn verify_certificate(
            _image: &str,
            _certificate: String,
            _certificate_chain: Option<Vec<String>>,
            _require_rekor_bundle: bool,
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
                    image: "ghcr.io/kubewarden/test-verify-image-signatures:*".to_string(),
                    pub_keys: vec!["key".to_string()],
                    annotations: None,
                },
            }],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the ghcr.io/kubewarden/test-verify-image-signatures container"),
            fixture_file: String::from("test_data/pod_creation_signed.json"),
            settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        let expected_mutation: serde_json::Value = json!(
        {
          "apiVersion": "v1",
          "kind": "Pod",
          "metadata": {
            "name": "nginx"
          },
          "spec": {
            "containers": [
              {
                "image": "ghcr.io/kubewarden/test-verify-image-signatures:signed@sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e",
                "name": "test-verify-image-signatures"
              }
            ]
          }
        });
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
                    image: "ghcr.io/kubewarden/test-verify-image-signatures:*".to_string(),
                    pub_keys: vec!["key".to_string()],
                    annotations: None,
                },
            }],
            modify_images_with_digest: false,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the ghcr.io/kubewarden/test-verify-image-signatures container"),
            fixture_file: String::from("test_data/pod_creation_signed.json"),
            settings,
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
            fixture_file: String::from("test_data/pod_creation_signed.json"),
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
                image: "ghcr.io/kubewarden/test-verify-image-signatures:*".to_string(),
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
            fixture_file: String::from("test_data/pod_creation_signed.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        let expected_mutation: serde_json::Value = json!(
        {
          "apiVersion": "v1",
          "kind": "Pod",
          "metadata": {
            "name": "nginx"
          },
          "spec": {
            "containers": [
              {
                "image": "ghcr.io/kubewarden/test-verify-image-signatures:signed@sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e",
                "name": "test-verify-image-signatures"
              }
            ]
          }
        });
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
                image: "ghcr.io/kubewarden/test-verify-image-signatures:*".to_string(),
                keyless: vec![],
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should fail when validating the ghcr.io/kubewarden/test-verify-image-signatures container"),
            fixture_file: String::from("test_data/pod_creation_signed.json"),
            settings,
            expected_validation_result: false,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, false)
    }

    #[test]
    #[serial]
    fn certificate_validation_pass_with_no_mutation() {
        let ctx = mock_sdk::verify_certificate_context();
        ctx.expect().times(1).returning(|_, _, _, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e"
                    .to_string(),
            })
        });

        let settings: Settings = Settings {
            signatures: vec![Signature::Certificate(Certificate {
                image: "ghcr.io/kubewarden/test-verify-image-signatures:*".to_string(),
                certificate: "cert".to_string(),
                certificate_chain: None,
                require_rekor_bundle: true,
                annotations: None,
            })],
            modify_images_with_digest: false,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the ghcr.io/kubewarden/test-verify-image-signatures container"),
            fixture_file: String::from("test_data/pod_creation_signed.json"),
            settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        assert!(response.mutated_object.is_none());
    }

    #[test]
    #[serial]
    fn certificate_validation_dont_pass() {
        let ctx = mock_sdk::verify_certificate_context();
        ctx.expect()
            .times(1)
            .returning(|_, _, _, _, _| Err(anyhow!("error")));

        let settings: Settings = Settings {
            signatures: vec![Signature::Certificate(Certificate {
                image: "ghcr.io/kubewarden/test-verify-image-signatures:*".to_string(),
                certificate: "cert".to_string(),
                certificate_chain: None,
                require_rekor_bundle: true,
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should fail when validating the nginx container"),
            fixture_file: String::from("test_data/pod_creation_signed.json"),
            settings,
            expected_validation_result: false,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, false);
        assert!(response.mutated_object.is_none());
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
            fixture_file: String::from("test_data/pod_creation_signed.json"),
            settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        assert!(response.mutated_object.is_none());
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

        let expected: serde_json::Value = json!(
                    {
          "apiVersion": "v1",
          "kind": "Pod",
          "metadata": {
            "name": "nginx"
          },
          "spec": {
            "containers": [
              {
                "image": "nginx@sha256:a3d850c2022ebf02156114178ef35298d63f83c740e7b5dd7777ff05898880f8",
                "name": "nginx"
              }
            ],
            "initContainers": [
              {
                "image": "init@sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e",
                "name": "init"
              }
            ]
          }
        }
                );
        assert_eq!(response.mutated_object.unwrap(), expected);
    }

    #[test]
    #[serial]
    fn keyless_validation_pass_and_dont_mutate_if_digest_is_present() {
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
            fixture_file: String::from("test_data/pod_creation_with_digest.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        assert!(response.mutated_object.is_none())
    }

    #[test]
    #[serial]
    fn keyless_prefix_validation_pass_and_dont_mutate_if_digest_is_present() {
        let ctx = mock_sdk::verify_keyless_prefix_match_context();
        ctx.expect().times(1).returning(|_, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e"
                    .to_string(),
            })
        });

        let settings: Settings = Settings {
            signatures: vec![Signature::KeylessPrefix(KeylessPrefix {
                image: "nginx:*".to_string(),
                keyless_prefix: vec![KeylessPrefixInfo {
                    issuer: "issuer".to_string(),
                    url_prefix: "subject".to_string(),
                }],
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the nginx container"),
            fixture_file: String::from("test_data/pod_creation_with_digest.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        assert!(response.mutated_object.is_none())
    }

    #[test]
    #[serial]
    fn keyless_github_action_validation_pass_and_dont_mutate_if_digest_is_present() {
        let ctx = mock_sdk::verify_keyless_github_actions_context();
        ctx.expect().times(1).returning(|_, _, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "sha256:89102e348749bb17a6a651a4b2a17420e1a66d2a44a675b981973d49a5af3a5e"
                    .to_string(),
            })
        });

        let settings: Settings = Settings {
            signatures: vec![Signature::GithubActions(GithubActions {
                image: "nginx:*".to_string(),
                github_actions: KeylessGithubActionsInfo {
                    owner: "owner".to_string(),
                    repo: Some("repo".to_string()),
                },
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should successfully validate the nginx container"),
            fixture_file: String::from("test_data/pod_creation_with_digest.json"),
            settings: settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        assert!(response.mutated_object.is_none())
    }

    fn resource_validation_pass(file: &str) {
        let ctx = mock_sdk::verify_keyless_exact_match_context();
        ctx.expect().times(1).returning(|_, _, _| {
            Ok(VerificationResponse {
                is_trusted: true,
                digest: "".to_string(),
            })
        });

        let settings: Settings = Settings {
            signatures: vec![Signature::Keyless(Keyless {
                image: "*".to_string(),
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
            fixture_file: String::from(file),
            settings,
            expected_validation_result: true,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, true);
        assert!(response.mutated_object.is_none())
    }

    fn resource_validation_reject(file: &str) {
        let ctx = mock_sdk::verify_keyless_exact_match_context();
        ctx.expect()
            .times(1)
            .returning(|_, _, _| Err(anyhow!("error")));

        let settings: Settings = Settings {
            signatures: vec![Signature::Keyless(Keyless {
                image: "*".to_string(),
                keyless: vec![KeylessInfo {
                    issuer: "issuer".to_string(),
                    subject: "subject".to_string(),
                }],
                annotations: None,
            })],
            modify_images_with_digest: true,
        };

        let tc = Testcase {
            name: String::from("It should failed validation"),
            fixture_file: String::from(file),
            settings,
            expected_validation_result: false,
        };

        let response = tc.eval(validate).unwrap();
        assert_eq!(response.accepted, false);
        assert!(response.mutated_object.is_none())
    }

    #[test]
    #[serial]
    fn resources_validation() {
        resource_validation_pass("test_data/deployment_creation_signed.json");
        resource_validation_pass("test_data/statefulset_creation_signed.json");
        resource_validation_pass("test_data/daemonset_creation_signed.json");
        resource_validation_pass("test_data/replicaset_creation_signed.json");
        resource_validation_pass("test_data/replicationcontroller_creation_signed.json");
        resource_validation_pass("test_data/cronjob_creation_signed.json");
        resource_validation_pass("test_data/job_creation_signed.json");

        resource_validation_reject("test_data/deployment_creation_unsigned.json");
        resource_validation_reject("test_data/statefulset_creation_unsigned.json");
        resource_validation_reject("test_data/daemonset_creation_unsigned.json");
        resource_validation_reject("test_data/replicaset_creation_unsigned.json");
        resource_validation_reject("test_data/replicationcontroller_creation_unsigned.json");
        resource_validation_reject("test_data/cronjob_creation_unsigned.json");
        resource_validation_reject("test_data/job_creation_unsigned.json");
    }
}
