//! CAIP-2 network identifiers (core spec, section 11.1: `{namespace}:{reference}`).
//!
//! The spec only requires the two-part shape. The grammar below is CAIP-2's own (namespace: 3 to 8 characters in
//! `[-a-z0-9]`, reference: 1 to 32 characters in `[-_a-zA-Z0-9]`), which every example in the spec satisfies.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A parsed CAIP-2 identifier such as `eip155:84532`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Caip2 {
    namespace: String,
    reference: String,
}

/// Why a string is not a CAIP-2 identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Caip2Error {
    /// No colon separating namespace and reference.
    #[error("expected `namespace:reference`, found no colon in {0:?}")]
    MissingSeparator(String),
    /// The namespace part breaks the CAIP-2 grammar.
    #[error("namespace {0:?} must be 3 to 8 characters of [-a-z0-9]")]
    Namespace(String),
    /// The reference part breaks the CAIP-2 grammar.
    #[error("reference {0:?} must be 1 to 32 characters of [-_a-zA-Z0-9]")]
    Reference(String),
}

impl Caip2 {
    /// The namespace, for example `eip155` or `solana`.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The reference, for example `84532`.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Whether this is an EVM network (`eip155` namespace).
    pub fn is_evm(&self) -> bool {
        self.namespace == "eip155"
    }

    /// Whether this is a Solana network (`solana` namespace).
    pub fn is_svm(&self) -> bool {
        self.namespace == "solana"
    }

    /// The EVM chain id, when the namespace is `eip155` and the reference is a decimal number.
    pub fn evm_chain_id(&self) -> Option<u64> {
        self.is_evm().then(|| self.reference.parse().ok()).flatten()
    }

    /// Whether the identifier matches a CAIP-2 pattern as used in `SupportedResponse.signers`
    /// (`eip155:*` matches every EVM network; an exact identifier matches only itself).
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        match pattern.split_once(':') {
            Some((namespace, "*")) => namespace == self.namespace,
            Some((namespace, reference)) => namespace == self.namespace && reference == self.reference,
            None => false,
        }
    }
}

impl FromStr for Caip2 {
    type Err = Caip2Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (namespace, reference) = s
            .split_once(':')
            .ok_or_else(|| Caip2Error::MissingSeparator(s.to_owned()))?;
        let namespace_ok = (3..=8).contains(&namespace.len())
            && namespace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !namespace_ok {
            return Err(Caip2Error::Namespace(namespace.to_owned()));
        }
        let reference_ok = (1..=32).contains(&reference.len())
            && reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !reference_ok {
            return Err(Caip2Error::Reference(reference.to_owned()));
        }
        Ok(Self {
            namespace: namespace.to_owned(),
            reference: reference.to_owned(),
        })
    }
}

impl TryFrom<String> for Caip2 {
    type Error = Caip2Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Caip2> for String {
    fn from(value: Caip2) -> Self {
        value.to_string()
    }
}

impl fmt::Display for Caip2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_spec_examples() {
        for (text, evm, chain) in [
            ("eip155:84532", true, Some(84532)),
            ("eip155:8453", true, Some(8453)),
            ("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", false, None),
            ("ach:us", false, None),
            ("sepa:eu", false, None),
        ] {
            let id: Caip2 = text.parse().unwrap();
            assert_eq!(id.is_evm(), evm);
            assert_eq!(id.evm_chain_id(), chain);
            assert_eq!(id.to_string(), text);
        }
    }

    #[test]
    fn rejects_malformed_identifiers() {
        assert!(matches!(
            "eip15584532".parse::<Caip2>(),
            Err(Caip2Error::MissingSeparator(_))
        ));
        assert!(matches!(
            "EIP155:1".parse::<Caip2>(),
            Err(Caip2Error::Namespace(_))
        ));
        assert!(matches!("ab:1".parse::<Caip2>(), Err(Caip2Error::Namespace(_))));
        assert!(matches!(
            "eip155:".parse::<Caip2>(),
            Err(Caip2Error::Reference(_))
        ));
        assert!(matches!(
            "eip155:with space".parse::<Caip2>(),
            Err(Caip2Error::Reference(_))
        ));
    }

    #[test]
    fn matches_signer_patterns() {
        let base: Caip2 = "eip155:84532".parse().unwrap();
        assert!(base.matches_pattern("eip155:*"));
        assert!(base.matches_pattern("eip155:84532"));
        assert!(!base.matches_pattern("eip155:8453"));
        assert!(!base.matches_pattern("solana:*"));
        assert!(!base.matches_pattern("*"));
    }

    #[test]
    fn serde_uses_the_string_form() {
        let json = serde_json::to_string(&"eip155:84532".parse::<Caip2>().unwrap()).unwrap();
        assert_eq!(json, "\"eip155:84532\"");
        assert!(serde_json::from_str::<Caip2>("\"nonsense\"").is_err());
    }
}
