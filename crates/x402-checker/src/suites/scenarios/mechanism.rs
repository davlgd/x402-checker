//! Which offer family the suite pays through, and how a payment is built for it.

use super::*;

/// Which offer of the server the suite drives its payments through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MechanismKind {
    /// `exact` with an EIP-3009 authorization on an `eip155` network: a real signature by a throwaway key.
    #[default]
    Evm,
    /// `exact` with a transaction on a `solana` network: random bytes stand for the transaction, since the scripted
    /// facilitator reads none. This exercises the server's Solana path, not a wallet.
    Svm,
}

/// How the suite builds a payment for the chosen offer, and the transaction identifiers the scripted facilitator
/// answers with in that family (hex hashes on EVM, base58 signatures on Solana, as each scheme spells them).
pub(super) enum Mechanism {
    Evm(Box<(Eip3009Offer, Payer)>),
    Svm,
}

impl Mechanism {
    /// The transaction the default script answers with.
    pub(super) fn happy_tx(&self) -> &'static str {
        match self {
            Self::Evm(_) => "0xabababababababababababababababababababababababababababababababab",
            Self::Svm => {
                "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
            }
        }
    }

    /// A different transaction, so that a new settlement can be told from a cached receipt.
    pub(super) fn replay_tx(&self) -> &'static str {
        match self {
            Self::Evm(_) => "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            Self::Svm => {
                "3AsdoALgZFuq2oUVWrDYhg2pNeaLJKPLf8hU2mQ6U8qJxeJ6hsrPVpMn9ma39DtfYCrDQSvngWRP8NnTpEhezJpE"
            }
        }
    }

    /// The scheme-specific `payload` of one fresh payment.
    pub(super) fn payload(&self) -> Value {
        match self {
            Self::Evm(inner) => {
                let (evm, payer) = inner.as_ref();
                let now = Timestamp::now().as_second().max(0).unsigned_abs();
                payer
                    .sign(evm, &AuthorizationParams::honest(evm, now, 300))
                    .to_value()
            }
            Self::Svm => {
                // 64 random bytes: a different "transaction" each time, never a real one
                let bytes: Vec<u8> = [x402_checker_evm::random_nonce(), x402_checker_evm::random_nonce()]
                    .iter()
                    .flat_map(|n| n.0)
                    .collect();
                json!({ "transaction": STANDARD.encode(bytes) })
            }
        }
    }
}
