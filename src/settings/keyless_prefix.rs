use kubewarden::host_capabilities::verification::KeylessPrefixInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use validator::Validate;

#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeylessPrefix {
    /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
    #[validate(length(min = 1))]
    pub(crate) image: String,
    /// List of keyless signatures that must be found
    #[validate(length(min = 1))]
    pub(crate) keyless_prefix: Vec<KeylessPrefixInfo>,
    /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
    pub(crate) annotations: Option<HashMap<String, String>>,
}

impl fmt::Display for KeylessPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyless signature for image {}", self.image)
    }
}
