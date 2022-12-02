use kubewarden::host_capabilities::verification::KeylessInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use validator::Validate;

#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Keyless {
    #[validate(length(min = 1))]
    pub(crate) image: String,
    pub(crate) keyless: Vec<KeylessInfo>,
    pub(crate) annotations: Option<HashMap<String, String>>,
}

impl fmt::Display for Keyless {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyless signature for image {}", self.image)
    }
}
