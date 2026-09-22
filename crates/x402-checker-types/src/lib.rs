//! Wire types of the x402 v2 protocol.
//!
//! Everything here mirrors the core specification (`spec/x402-specification-v2.md`, section 5 and 7) and the HTTP
//! transport (`spec/transports-v2_http.md`). The crate has no I/O and no opinion: it parses, validates the shape of,
//! and serialises the objects that travel between clients, resource servers and facilitators.
//!
//! Field names follow the JSON names of the spec (camelCase). The typed structs are a convenience, not a faithful
//! copy: unknown members are dropped, `null` and absent are the same, optional members are omitted on output and
//! the member order is the struct's. A check that must judge what a server actually sent reads the JSON text that
//! [`decode_header`] returns alongside the typed value ([`Decoded::json`], the decoded bytes kept as a string), or
//! parses it into a generic JSON value. Additional members are rejected nowhere, since the spec never forbids them.

pub mod base58;
pub mod codec;
pub mod error_codes;
pub mod headers;
pub mod network;
pub mod types;

pub use codec::{Alphabet, Base64Variant, DecodeError, Decoded, Padding, decode_header, encode_header};
pub use network::{Caip2, Caip2Error};
pub use types::{
    Extensions, FacilitatorRequest, PaymentPayload, PaymentRequired, PaymentRequirements, ResourceInfo,
    SettleResponse, SupportedKind, SupportedResponse, VerifyResponse, X402_VERSION,
};
