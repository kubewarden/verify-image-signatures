use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use validator::Validate;

use super::validation_helpers::validate_vector_of_pem_strings;

#[derive(Serialize, Deserialize, Validate, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PubKeys {
    #[validate(length(min = 1))]
    pub(crate) image: String,
    #[validate(length(min = 1), custom(function = "validate_vector_of_pem_strings"))]
    pub(crate) pub_keys: Vec<String>,
    pub(crate) annotations: Option<BTreeMap<String, String>>,
}

impl fmt::Display for PubKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pub key signature for image {}", self.image)
    }
}

#[cfg(test)]
mod tests {
    use super::super::validation_helpers::tests::PEM_DATA;
    use super::*;
    use validator::Validate;

    #[test]
    fn validation_pass() {
        let pub_keys = PubKeys {
            image: "foo".to_string(),
            pub_keys: vec![PEM_DATA.to_string()],
            annotations: None,
        };
        assert!(pub_keys.validate().is_ok());
    }

    #[test]
    fn validation_fails_because_missing_values() {
        let pub_keys = PubKeys {
            image: "".to_string(),
            pub_keys: vec![PEM_DATA.to_string()],
            annotations: None,
        };

        assert!(pub_keys.validate().is_err());
    }

    #[test]
    fn validation_fails_because_pub_key_is_not_pem_encoded() {
        let pub_keys = PubKeys {
            image: "foo".to_string(),
            pub_keys: vec!["hello".to_string()],
            annotations: None,
        };

        assert!(pub_keys.validate().is_err());

        let pub_keys = PubKeys {
            image: "foo".to_string(),
            pub_keys: vec![PEM_DATA.to_string(), "hello".to_string()],
            annotations: None,
        };

        assert!(pub_keys.validate().is_err());
    }
}
