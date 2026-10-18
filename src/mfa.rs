//! MFA one-time codes and MFA device selection.

use std::fmt;
use std::str::FromStr;

/// A six-digit one-time code from a virtual or hardware TOTP device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MfaCode(String);

impl MfaCode {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for MfaCode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.trim();
        // ASCII digits only: `char::is_numeric` accepts Unicode digits (e.g. "٦٦٦",
        // superscripts) and `str::len` counts bytes, so a looser check could pass a
        // non-numeric, non-6-char code. All-ASCII-digit guarantees len == char count.
        if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Self(code.to_owned()))
        } else {
            Err("MFA code must be exactly 6 digits")
        }
    }
}

impl fmt::Display for MfaCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Pick the device to authenticate with from the user's MFA device serials.
/// FIDO security keys (`...:u2f/...`) cannot produce the one-time codes that
/// GetSessionToken needs, so they are skipped.
pub fn select_device(serials: impl IntoIterator<Item = String>) -> Option<String> {
    serials.into_iter().find(|serial| !serial.contains(":u2f/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<MfaCode, &'static str> {
        s.parse()
    }

    #[test]
    fn test_parse_valid() {
        assert_eq!(parse("123456").unwrap().as_str(), "123456");
        assert_eq!(parse("000000").unwrap().as_str(), "000000");
        assert_eq!(parse("999999").unwrap().to_string(), "999999");
    }

    #[test]
    fn test_parse_trims_surrounding_whitespace() {
        assert_eq!(parse(" 123456\n").unwrap().as_str(), "123456");
    }

    #[test]
    fn test_parse_invalid_length() {
        assert!(parse("12345").is_err());
        assert!(parse("1234567").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn test_parse_invalid_characters() {
        assert!(parse("12345a").is_err());
        assert!(parse("abcdef").is_err());
        assert!(parse("12-456").is_err());
        assert!(parse("123 56").is_err());
    }

    #[test]
    fn test_parse_rejects_non_ascii_digits() {
        // Arabic-Indic digits: 6 chars but 12 bytes, all `char::is_numeric`.
        assert!(parse("٦٦٦٦٦٦").is_err());
        // Fullwidth digits: 6 chars, 18 bytes.
        assert!(parse("１２３４５６").is_err());
        // Superscript two (U+00B2): 2 bytes each, so 3 of them is 6 bytes and
        // `is_numeric` — the case a `len() == 6` check wrongly accepted.
        assert!(parse("²²²").is_err());
    }

    #[test]
    fn test_select_device_skips_security_keys() {
        let devices = [
            "arn:aws:iam::123456789012:u2f/user/alice/yubikey-ABCD".to_owned(),
            "arn:aws:iam::123456789012:mfa/alice".to_owned(),
        ];
        assert_eq!(
            select_device(devices),
            Some("arn:aws:iam::123456789012:mfa/alice".to_owned())
        );
    }

    #[test]
    fn test_select_device_keeps_first_usable() {
        let devices = ["GAHT12345678".to_owned(), "arn:aws:iam::1:mfa/a".to_owned()];
        assert_eq!(select_device(devices), Some("GAHT12345678".to_owned()));
    }

    #[test]
    fn test_select_device_none_usable() {
        assert_eq!(select_device(Vec::new()), None);
        assert_eq!(
            select_device(["arn:aws:iam::1:u2f/user/a/key".to_owned()]),
            None
        );
    }
}
