use validator::ValidationError;

pub(crate) fn validate_vector_of_pem_strings(data: &[String]) -> Result<(), ValidationError> {
    let violations = data
        .iter()
        .filter(|s| pem::parse(s.as_bytes()).is_err())
        .count();

    if violations == 0 {
        Ok(())
    } else {
        Err(ValidationError::new("non-PEM data found"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const PEM_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIICSzCCAfCgAwIBAgIUHKusfkyBA2FHmSje5pEiQAE5L4AwCgYIKoZIzj0EAwIw
gYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdCYXZhcmlhMRIwEAYDVQQHEwlOdXJl
bWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4xGzAZBgNVBAsTEkt1YmV3YXJkZW4g
Um9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRlbiBSb290IENBMB4XDTIyMTEyOTE2
MzMwMFoXDTI3MTEyODE2MzMwMFowgYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdC
YXZhcmlhMRIwEAYDVQQHEwlOdXJlbWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4x
GzAZBgNVBAsTEkt1YmV3YXJkZW4gUm9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRl
biBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJvLruo6Lk6thhFGf
1EoVJblAExTC44nd8Fy2Qmtlu7Gxfc3YCnadvYG+VJGHwV8dW1iRYD/oEoeGIofH
3KRhXqNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFD12Y/IxivzMT/4PqYXSQ9C1wH/HMAoGCCqGSM49BAMCA0kAMEYCIQCVF8AT
c9UaPJPbF9lm7ItwQnciJbarLBKi4vPEFFET/gIhANw6VUfxS55hdSCEF27+jvjy
uDQIMUZKKXu/8si37BkB
-----END CERTIFICATE-----
"#;

    #[test]
    fn pem_strings_validation() {
        let data = vec![PEM_DATA.to_string()];
        assert!(validate_vector_of_pem_strings(&data).is_ok());

        let data = vec![PEM_DATA.to_string(), "foo".to_string()];
        assert!(validate_vector_of_pem_strings(&data).is_err());

        let data = vec!["foo".to_string()];
        assert!(validate_vector_of_pem_strings(&data).is_err());
    }
}
