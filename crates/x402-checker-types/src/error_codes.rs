//! Standard error codes (core spec, section 9). They "may be returned by facilitators or resource servers": using
//! another code is not a violation, using one of these with a different meaning is.

/// Client does not have enough tokens to complete the payment.
pub const INSUFFICIENT_FUNDS: &str = "insufficient_funds";
/// Authorization not yet valid (before `validAfter`).
pub const INVALID_EXACT_EVM_PAYLOAD_AUTHORIZATION_VALID_AFTER: &str =
    "invalid_exact_evm_payload_authorization_valid_after";
/// Authorization expired (after `validBefore`).
pub const INVALID_EXACT_EVM_PAYLOAD_AUTHORIZATION_VALID_BEFORE: &str =
    "invalid_exact_evm_payload_authorization_valid_before";
/// Amount does not exactly match the required amount.
pub const INVALID_EXACT_EVM_PAYLOAD_AUTHORIZATION_VALUE_MISMATCH: &str =
    "invalid_exact_evm_payload_authorization_value_mismatch";
/// Signature invalid or improperly signed.
pub const INVALID_EXACT_EVM_PAYLOAD_SIGNATURE: &str = "invalid_exact_evm_payload_signature";
/// Recipient does not match the payment requirements.
pub const INVALID_EXACT_EVM_PAYLOAD_RECIPIENT_MISMATCH: &str = "invalid_exact_evm_payload_recipient_mismatch";
/// Network not supported.
pub const INVALID_NETWORK: &str = "invalid_network";
/// Payment payload malformed.
pub const INVALID_PAYLOAD: &str = "invalid_payload";
/// Payment requirements malformed.
pub const INVALID_PAYMENT_REQUIREMENTS: &str = "invalid_payment_requirements";
/// Scheme not supported.
pub const INVALID_SCHEME: &str = "invalid_scheme";
/// Scheme not supported by the facilitator.
pub const UNSUPPORTED_SCHEME: &str = "unsupported_scheme";
/// Protocol version not supported.
pub const INVALID_X402_VERSION: &str = "invalid_x402_version";
/// Blockchain transaction failed or was rejected.
pub const INVALID_TRANSACTION_STATE: &str = "invalid_transaction_state";
/// Unexpected error during verification.
pub const UNEXPECTED_VERIFY_ERROR: &str = "unexpected_verify_error";
/// Unexpected error during settlement.
pub const UNEXPECTED_SETTLE_ERROR: &str = "unexpected_settle_error";
/// Settlement broadcast but not confirmed; non-terminal; the response must carry the transaction hash.
pub const SETTLEMENT_PENDING: &str = "settlement_pending";

/// Every code of section 9, in the order of the spec.
pub const ALL: [&str; 16] = [
    INSUFFICIENT_FUNDS,
    INVALID_EXACT_EVM_PAYLOAD_AUTHORIZATION_VALID_AFTER,
    INVALID_EXACT_EVM_PAYLOAD_AUTHORIZATION_VALID_BEFORE,
    INVALID_EXACT_EVM_PAYLOAD_AUTHORIZATION_VALUE_MISMATCH,
    INVALID_EXACT_EVM_PAYLOAD_SIGNATURE,
    INVALID_EXACT_EVM_PAYLOAD_RECIPIENT_MISMATCH,
    INVALID_NETWORK,
    INVALID_PAYLOAD,
    INVALID_PAYMENT_REQUIREMENTS,
    INVALID_SCHEME,
    UNSUPPORTED_SCHEME,
    INVALID_X402_VERSION,
    INVALID_TRANSACTION_STATE,
    UNEXPECTED_VERIFY_ERROR,
    UNEXPECTED_SETTLE_ERROR,
    SETTLEMENT_PENDING,
];

/// Whether `code` is one of the standard codes.
pub fn is_standard(code: &str) -> bool {
    ALL.contains(&code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_the_standard_codes() {
        assert!(is_standard("settlement_pending"));
        assert!(is_standard("invalid_exact_evm_payload_signature"));
        assert!(!is_standard("payment_already_settled"));
        assert_eq!(ALL.len(), 16);
    }
}
