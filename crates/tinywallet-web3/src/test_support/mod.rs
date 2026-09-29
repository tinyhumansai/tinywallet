//! Shared fakes for the crate's unit tests.
//!
//! Every seam has a fake here, so a test drives the real engine against canned
//! chain answers and inspects what it asked for. No environment variables, no
//! sockets and no global state: two tests never see each other's quotes.
//!
//! - [`FakeTransport`] — canned chain responses plus a call log.
//! - [`FakeSigner`] — real accounts derived from the well-known test mnemonic;
//!   records what it was asked to sign.
//! - [`FakeWalletAccounts`], [`FakeRpcEndpoints`], [`FakeQuoteScope`],
//!   [`FakeBackend`] — the remaining seams.
//! - [`Rig`] and [`ServiceRig`] — an engine (and service) wired to all of them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod backend;
mod rig;
mod samples;
mod seams;
mod signer;
mod transport;

pub(crate) use backend::FakeBackend;
pub(crate) use rig::{Rig, ServiceRig};
pub(crate) use samples::{
    TEST_MNEMONIC, configured_status, owner_a, owner_b, prepared_quote, sample_account,
    sample_address,
};
pub(crate) use seams::{FakeQuoteScope, FakeRpcEndpoints, FakeWalletAccounts};
pub(crate) use signer::{FakeSigner, SignerCall};
pub(crate) use transport::{Call, FakeTransport};
