//! Test doubles for x402 v2 resource servers.
//!
//! Two small HTTP servers that a resource server under test can be pointed at:
//!
//! - a **scripted facilitator** serving `GET /supported`, `POST /verify` and `POST /settle` (core spec, section 7)
//!   whose answers are chosen by a [`Script`] that the test changes between scenarios;
//! - a **witness backend** answering any request so that a test can tell whether, when and how the protected
//!   resource was executed.
//!
//! Both record every call they receive in a shared [`Recorder`], in arrival order with timestamps, so that a test
//! can reason about sequences (verify, then backend, then settle) and about what the server sent.

pub mod facilitator;
pub mod recorder;
pub mod witness;

pub use facilitator::{
    DEFAULT_SVM_FEE_PAYER, Facilitator, FacilitatorConfig, SVM_PAYER, Script, SettleOutcome, VerifyOutcome,
};
pub use recorder::{Call, Endpoint, Recorder};
pub use witness::{Witness, WitnessScript};
