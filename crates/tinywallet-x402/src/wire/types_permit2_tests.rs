//! Tests for the Permit2 (`upto`) proof's wire shape and the deadline every
//! EVM proof exposes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{EvmAuthorization, EvmPaymentProof, PaymentProof, SolanaPaymentProof};

/// The payload example of the x402 `upto` EVM specification, verbatim.
const SPEC_UPTO_PAYLOAD: &str = r#"{
    "signature": "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
    "permit2Authorization": {
      "permitted": {"token": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "amount": "5000000"},
      "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      "spender": "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002",
      "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480",
      "deadline": "1740672154",
      "witness": {
        "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "facilitator": "0xFacilitatorAddress1234567890123456789012",
        "validAfter": "1740672089"
      }
    }
}"#;

#[test]
fn the_spec_upto_payload_reads_as_a_permit2_proof_and_round_trips() {
    let raw: serde_json::Value = serde_json::from_str(SPEC_UPTO_PAYLOAD).unwrap();
    let proof: PaymentProof = serde_json::from_value(raw.clone()).unwrap();
    let PaymentProof::Permit2(permit2) = &proof else {
        panic!("expected a Permit2 proof, got {proof:?}");
    };
    assert_eq!(
        permit2.permit2_authorization.witness.valid_after,
        "1740672089"
    );
    assert_eq!(serde_json::to_value(&proof).unwrap(), raw);
}

#[test]
fn every_evm_proof_exposes_its_deadline() {
    let raw: serde_json::Value = serde_json::from_str(SPEC_UPTO_PAYLOAD).unwrap();
    let permit2: PaymentProof = serde_json::from_value(raw).unwrap();
    assert_eq!(permit2.authorization_deadline_secs(), Some(1_740_672_154));

    let eip3009 = PaymentProof::Evm(EvmPaymentProof {
        signature: "0x".into(),
        authorization: EvmAuthorization {
            from: "f".into(),
            to: "t".into(),
            value: "1".into(),
            valid_after: "0".into(),
            valid_before: "1800000000".into(),
            nonce: "0x".into(),
        },
    });
    assert_eq!(eip3009.authorization_deadline_secs(), Some(1_800_000_000));

    let solana = PaymentProof::Solana(SolanaPaymentProof {
        transaction: "tx".into(),
    });
    assert_eq!(solana.authorization_deadline_secs(), None);
}
