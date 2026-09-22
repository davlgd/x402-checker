//! The `exact` scheme on EVM networks with the `eip3009` asset transfer method
//! (`spec/schemes_exact_scheme_exact_evm.md`, section 1).
//!
//! A payment is an EIP-3009 `TransferWithAuthorization` message signed with EIP-712 over the token's domain
//! (`name` and `version` from `accepts[].extra`, `chainId` from the CAIP-2 reference, `verifyingContract` from
//! `asset`). This crate builds and signs such authorizations, recovers the signer of an existing one, and turns
//! the result into the `PaymentPayload.payload` object of the wire format. It talks to no network.

use alloy_primitives::{Address, B256, FixedBytes, Signature, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{Eip712Domain, SolStruct, eip712_domain, sol};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x402_checker_types::{Caip2, PaymentRequirements};

/// The `assetTransferMethod` value of this module; the default when `accepts[].extra` omits it.
pub const ASSET_TRANSFER_METHOD: &str = "eip3009";

/// The scheme identifier.
pub const SCHEME: &str = "exact";

sol! {
    /// EIP-3009 `TransferWithAuthorization` typed data, as signed by the payer.
    #[derive(Debug, PartialEq, Eq)]
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// The `authorization` object of an `eip3009` payload (core spec section 5.2.2): every field is a string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// Payer address.
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// Amount in atomic units, decimal string.
    pub value: String,
    /// Unix timestamp (seconds) from which the authorization is valid, decimal string.
    pub valid_after: String,
    /// Unix timestamp (seconds) at which the authorization expires, decimal string.
    pub valid_before: String,
    /// 32 random bytes, `0x`-prefixed hex.
    pub nonce: String,
}

/// The `payload` object of an `eip3009` payment: the signature and the parameters it covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip3009Payload {
    /// 65-byte secp256k1 signature, `0x`-prefixed hex.
    pub signature: String,
    /// The signed parameters.
    pub authorization: Authorization,
}

impl Eip3009Payload {
    /// The payload as the JSON value carried in `PaymentPayload.payload`.
    ///
    /// # Panics
    ///
    /// Never in practice: the payload only holds strings.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("an eip3009 payload only holds strings")
    }
}

/// What the tool needs to know about an `exact` EVM offer before it can sign for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip3009Offer {
    /// EVM chain id from the CAIP-2 network.
    pub chain_id: u64,
    /// Token contract, the EIP-712 `verifyingContract`.
    pub asset: Address,
    /// Recipient.
    pub pay_to: Address,
    /// Amount in atomic units.
    pub amount: U256,
    /// EIP-712 domain name of the token (`extra.name`).
    pub name: String,
    /// EIP-712 domain version of the token (`extra.version`).
    pub version: String,
}

/// Why an `accepts[]` entry cannot be paid by this module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OfferError {
    /// The scheme is not `exact`.
    #[error("scheme is {0:?}, this module pays `exact` only")]
    Scheme(String),
    /// The network is not a valid CAIP-2 identifier.
    #[error("network {0:?} is not a CAIP-2 identifier")]
    Network(String),
    /// The network is not an EVM chain with a numeric chain id.
    #[error("network {0} is not an `eip155` network with a numeric chain id")]
    NotEvm(String),
    /// `extra.assetTransferMethod` names another method.
    #[error("assetTransferMethod is {0:?}, this module pays `eip3009` only")]
    AssetTransferMethod(String),
    /// `extra.paymentFlow` names a flow this module does not implement.
    #[error("paymentFlow is {0:?}, this module pays the `authorization` flow only")]
    PaymentFlow(String),
    /// A required `extra` key is missing or not a string.
    #[error("extra.{0} is required by the eip3009 method and missing or not a string")]
    MissingExtra(&'static str),
    /// `asset` or `payTo` is not a 20-byte hex address.
    #[error("{field} {value:?} is not an EVM address")]
    Address {
        /// Which field.
        field: &'static str,
        /// The offending value.
        value: String,
    },
    /// `amount` is not a decimal integer that fits in 256 bits.
    #[error("amount {0:?} is not a non-negative decimal integer")]
    Amount(String),
}

impl Eip3009Offer {
    /// Reads an `accepts[]` entry, refusing anything this module cannot pay for.
    pub fn from_requirements(offer: &PaymentRequirements) -> Result<Self, OfferError> {
        if offer.scheme != SCHEME {
            return Err(OfferError::Scheme(offer.scheme.clone()));
        }
        let network: Caip2 = offer
            .network
            .parse()
            .map_err(|_| OfferError::Network(offer.network.clone()))?;
        let chain_id = network
            .evm_chain_id()
            .ok_or_else(|| OfferError::NotEvm(network.to_string()))?;
        match offer.asset_transfer_method() {
            Ok(None | Some(ASSET_TRANSFER_METHOD)) => {}
            Ok(Some(other)) => return Err(OfferError::AssetTransferMethod(other.to_owned())),
            Err(value) => return Err(OfferError::AssetTransferMethod(value.to_string())),
        }
        match offer.payment_flow() {
            Ok(None | Some("authorization")) => {}
            Ok(Some(other)) => return Err(OfferError::PaymentFlow(other.to_owned())),
            Err(value) => return Err(OfferError::PaymentFlow(value.to_string())),
        }
        let extra_string = |key: &'static str| {
            offer
                .extra
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(OfferError::MissingExtra(key))
        };
        let address = |field: &'static str, value: &str| {
            value.parse::<Address>().map_err(|_| OfferError::Address {
                field,
                value: value.to_owned(),
            })
        };
        Ok(Self {
            chain_id,
            asset: address("asset", &offer.asset)?,
            pay_to: address("payTo", &offer.pay_to)?,
            amount: parse_amount(&offer.amount).ok_or_else(|| OfferError::Amount(offer.amount.clone()))?,
            name: extra_string("name")?,
            version: extra_string("version")?,
        })
    }

    /// The EIP-712 domain of the token for this offer.
    pub fn domain(&self) -> Eip712Domain {
        eip712_domain! {
            name: self.name.clone(),
            version: self.version.clone(),
            chain_id: self.chain_id,
            verifying_contract: self.asset,
        }
    }
}

fn parse_amount(text: &str) -> Option<U256> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| U256::from_str_radix(text, 10).ok())
        .flatten()
}

/// A payer: a local secp256k1 key.
#[derive(Clone)]
pub struct Payer {
    signer: PrivateKeySigner,
}

impl std::fmt::Debug for Payer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payer")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

/// The validity window of an authorization, in Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// `validAfter`.
    pub valid_after: u64,
    /// `validBefore`.
    pub valid_before: u64,
}

impl Window {
    /// A window open since `skew` seconds before `now` and closing `duration` seconds after it.
    pub fn around(now: u64, skew: u64, duration: u64) -> Self {
        Self {
            valid_after: now.saturating_sub(skew),
            valid_before: now.saturating_add(duration),
        }
    }
}

/// The parts of a payment the tool may want to bend on purpose (wrong recipient, wrong value, expired window).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationParams {
    /// Recipient; normally the offer's `payTo`.
    pub to: Address,
    /// Amount; normally the offer's `amount`.
    pub value: U256,
    /// Validity window.
    pub window: Window,
    /// 32-byte nonce; random when `None`.
    pub nonce: Option<B256>,
}

impl AuthorizationParams {
    /// The parameters an honest client would use for `offer`, valid from `now - 60s` for `duration` seconds.
    pub fn honest(offer: &Eip3009Offer, now: u64, duration: u64) -> Self {
        Self {
            to: offer.pay_to,
            value: offer.amount,
            window: Window::around(now, 60, duration),
            nonce: None,
        }
    }
}

impl Payer {
    /// A payer from a `0x`-prefixed 32-byte hex private key.
    pub fn from_private_key(hex: &str) -> Result<Self, alloy_signer_local::LocalSignerError> {
        Ok(Self { signer: hex.parse()? })
    }

    /// A fresh random key, for tests and dry runs.
    pub fn random() -> Self {
        Self {
            signer: PrivateKeySigner::random(),
        }
    }

    /// The payer's address.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Signs an EIP-3009 authorization for `offer` with the given parameters.
    ///
    /// # Panics
    ///
    /// Never in practice: signing with a local key cannot fail.
    pub fn sign(&self, offer: &Eip3009Offer, params: &AuthorizationParams) -> Eip3009Payload {
        let nonce = params.nonce.unwrap_or_else(random_nonce);
        let message = TransferWithAuthorization {
            from: self.address(),
            to: params.to,
            value: params.value,
            validAfter: U256::from(params.window.valid_after),
            validBefore: U256::from(params.window.valid_before),
            nonce,
        };
        let signature = self
            .signer
            .sign_typed_data_sync(&message, &offer.domain())
            .expect("local signing cannot fail");
        Eip3009Payload {
            signature: format!("0x{}", alloy_primitives::hex::encode(signature.as_bytes())),
            authorization: Authorization {
                from: message.from.to_string(),
                to: message.to.to_string(),
                value: message.value.to_string(),
                valid_after: message.validAfter.to_string(),
                valid_before: message.validBefore.to_string(),
                nonce: nonce.to_string(),
            },
        }
    }
}

/// Why a payload's signature cannot be checked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoverError {
    /// A field of the authorization is not in the expected format.
    #[error("authorization.{0} is malformed")]
    Field(&'static str),
    /// The signature is not 65 bytes of hex.
    #[error("signature is not a 65-byte hex string")]
    Signature,
    /// The signature does not recover to any address (invalid r, s or v).
    #[error("signature does not recover to an address")]
    Recovery,
}

/// Recovers the address that signed `payload` for `offer`, to compare with `authorization.from`.
pub fn recover_signer(offer: &Eip3009Offer, payload: &Eip3009Payload) -> Result<Address, RecoverError> {
    let a = &payload.authorization;
    let message = TransferWithAuthorization {
        from: a.from.parse().map_err(|_| RecoverError::Field("from"))?,
        to: a.to.parse().map_err(|_| RecoverError::Field("to"))?,
        value: parse_amount(&a.value).ok_or(RecoverError::Field("value"))?,
        validAfter: parse_amount(&a.valid_after).ok_or(RecoverError::Field("validAfter"))?,
        validBefore: parse_amount(&a.valid_before).ok_or(RecoverError::Field("validBefore"))?,
        nonce: a
            .nonce
            .parse::<FixedBytes<32>>()
            .map_err(|_| RecoverError::Field("nonce"))?,
    };
    let digest = message.eip712_signing_hash(&offer.domain());
    let signature = payload
        .signature
        .parse::<Signature>()
        .map_err(|_| RecoverError::Signature)?;
    signature
        .recover_address_from_prehash(&digest)
        .map_err(|_| RecoverError::Recovery)
}

/// A random 32-byte nonce, as EIP-3009 requires.
pub fn random_nonce() -> B256 {
    B256::from(rand::rng().random::<[u8; 32]>())
}

/// Keccak-256 of arbitrary bytes, exposed for callers that build payment identifiers.
pub fn keccak(bytes: &[u8]) -> B256 {
    keccak256(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offer of every example in the spec: USDC on Base Sepolia.
    fn spec_offer() -> Eip3009Offer {
        let requirements: PaymentRequirements = serde_json::from_value(serde_json::json!({
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 60,
            "extra": { "name": "USDC", "version": "2" }
        }))
        .unwrap();
        Eip3009Offer::from_requirements(&requirements).unwrap()
    }

    #[test]
    fn reads_the_spec_offer() {
        let offer = spec_offer();
        assert_eq!(offer.chain_id, 84532);
        assert_eq!(offer.amount, U256::from(10000));
        assert_eq!(offer.name, "USDC");
    }

    #[test]
    fn refuses_what_it_cannot_pay() {
        let mut base: PaymentRequirements = serde_json::from_value(serde_json::json!({
            "scheme": "exact", "network": "eip155:84532", "amount": "1", "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "maxTimeoutSeconds": 60, "extra": { "name": "USDC", "version": "2" }
        }))
        .unwrap();
        assert!(Eip3009Offer::from_requirements(&base).is_ok());

        let mut other = base.clone();
        other.scheme = "upto".into();
        assert!(matches!(
            Eip3009Offer::from_requirements(&other),
            Err(OfferError::Scheme(_))
        ));

        other = base.clone();
        other.network = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".into();
        assert!(matches!(
            Eip3009Offer::from_requirements(&other),
            Err(OfferError::NotEvm(_))
        ));

        other = base.clone();
        other.extra.insert("assetTransferMethod".into(), "permit2".into());
        assert!(matches!(
            Eip3009Offer::from_requirements(&other),
            Err(OfferError::AssetTransferMethod(_))
        ));

        other = base.clone();
        other.extra.insert("paymentFlow".into(), "upfront".into());
        assert!(matches!(
            Eip3009Offer::from_requirements(&other),
            Err(OfferError::PaymentFlow(_))
        ));

        other = base.clone();
        other.extra.insert("paymentFlow".into(), serde_json::json!(7));
        assert!(
            matches!(
                Eip3009Offer::from_requirements(&other),
                Err(OfferError::PaymentFlow(_))
            ),
            "a present key of the wrong type is not the default"
        );

        other = base.clone();
        other.extra.remove("version");
        assert!(matches!(
            Eip3009Offer::from_requirements(&other),
            Err(OfferError::MissingExtra("version"))
        ));

        other = base.clone();
        other.amount = "1.5".into();
        assert!(matches!(
            Eip3009Offer::from_requirements(&other),
            Err(OfferError::Amount(_))
        ));

        base.pay_to = "merchant".into();
        assert!(matches!(
            Eip3009Offer::from_requirements(&base),
            Err(OfferError::Address { field: "payTo", .. })
        ));
    }

    #[test]
    fn signs_and_recovers() {
        let offer = spec_offer();
        let payer = Payer::random();
        let payload = payer.sign(&offer, &AuthorizationParams::honest(&offer, 1_740_672_089, 60));
        assert_eq!(payload.signature.len(), 2 + 130, "65 bytes of hex");
        assert_eq!(payload.authorization.nonce.len(), 66);
        assert_eq!(payload.authorization.value, "10000");
        assert_eq!(payload.authorization.valid_after, "1740672029");
        assert_eq!(payload.authorization.valid_before, "1740672149");
        assert_eq!(recover_signer(&offer, &payload).unwrap(), payer.address());
        assert_eq!(payload.authorization.from, payer.address().to_string());
    }

    #[test]
    fn a_tampered_value_recovers_to_someone_else() {
        let offer = spec_offer();
        let payer = Payer::random();
        let mut payload = payer.sign(&offer, &AuthorizationParams::honest(&offer, 1_740_672_089, 60));
        payload.authorization.value = "10001".into();
        assert_ne!(recover_signer(&offer, &payload).unwrap(), payer.address());
    }

    #[test]
    fn the_spec_example_signature_recovers_to_its_from_address() {
        // Section 5.2.1 of the core spec and section 1 of the EVM binding show the same payload. If the example
        // was produced by a real signer, it recovers to `authorization.from`; this pins the typed data layout.
        let offer = spec_offer();
        let payload: Eip3009Payload = serde_json::from_value(serde_json::json!({
            "signature": "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
            "authorization": {
                "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
                "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                "value": "10000",
                "validAfter": "1740672089",
                "validBefore": "1740672154",
                "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
            }
        }))
        .unwrap();
        let recovered = recover_signer(&offer, &payload).unwrap();
        let expected: Address = "0x857b06519E91e3A54538791bDbb0E22373e36b66".parse().unwrap();
        assert_eq!(
            recovered, expected,
            "the spec example is a genuine signature over this typed data"
        );
    }

    #[test]
    fn payload_json_uses_the_wire_names() {
        let offer = spec_offer();
        let payload = Payer::random()
            .sign(&offer, &AuthorizationParams::honest(&offer, 0, 60))
            .to_value();
        let keys: Vec<_> = payload["authorization"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            ["from", "to", "value", "validAfter", "validBefore", "nonce"]
        );
    }
}
