use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use validator::Validate;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeylessGithubActionsInfo {
    /// owner of the repository. E.g: octocat
    pub(crate) owner: String,
    /// Optional - Repo of the GH Action workflow that signed the artifact. E.g: example-repo
    pub(crate) repo: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GithubActions {
    /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
    #[validate(length(min = 1))]
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
