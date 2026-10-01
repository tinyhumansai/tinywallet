#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{DUST_THRESHOLD, Transfer, Utxo, script_pubkey, select_coins};
use crate::tx::Error;

const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";
const PATH: &str = "m/84'/0'/0'/0/0";
/// The BIP-84 vector address, which the key below controls.
const FROM: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const TO: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const TXID: &str = "7f3b662ea8b6ff2e0e1a1f9bd0f1c39a6b8ba51e1b0f0e0d0c0b0a0908070605";

fn key() -> Vec<u8> {
    crate::key::derive(crate::Chain::Btc, VECTOR, PATH)
        .unwrap()
        .secret_bytes()
        .to_vec()
}

fn utxo(value: u64, vout: u32) -> Utxo {
    Utxo {
        txid: TXID.to_string(),
        vout,
        value,
    }
}

fn transfer(amount: u64, fee: u64) -> Transfer {
    Transfer {
        from: FROM.to_string(),
        to: TO.to_string(),
        amount,
        fee,
    }
}

#[test]
fn selection_takes_the_largest_coins_first() {
    let utxos = [utxo(1_000, 0), utxo(50_000, 1), utxo(10_000, 2)];
    let selection = select_coins(&utxos, 40_000).unwrap();
    assert_eq!(selection.inputs.len(), 1, "one big coin suffices");
    assert_eq!(selection.inputs[0].value, 50_000);
    assert_eq!(selection.change, 10_000);
}

#[test]
fn selection_accumulates_until_the_target_is_met() {
    let utxos = [utxo(10_000, 0), utxo(10_000, 1), utxo(10_000, 2)];
    let selection = select_coins(&utxos, 25_000).unwrap();
    assert_eq!(selection.inputs.len(), 3);
    assert_eq!(selection.change, 5_000);
}

#[test]
fn dust_change_is_folded_into_the_fee_not_emitted() {
    // A sub-dust output is unspendable and makes the transaction
    // unrelayable, so it must not be created.
    let utxos = [utxo(10_000 + DUST_THRESHOLD, 0)];
    let selection = select_coins(&utxos, 10_000).unwrap();
    assert_eq!(selection.change, 0, "dust surplus goes to the fee");

    let (tx, _) = transfer(9_000, 1_000 + DUST_THRESHOLD)
        .build(&utxos)
        .unwrap();
    assert_eq!(tx.output.len(), 1, "no dust change output");
}

#[test]
fn change_above_the_dust_threshold_is_emitted() {
    let utxos = [utxo(100_000, 0)];
    let (tx, selection) = transfer(50_000, 1_000).build(&utxos).unwrap();
    assert_eq!(selection.change, 49_000);
    assert_eq!(tx.output.len(), 2, "recipient plus change");
    assert_eq!(tx.output[1].value.to_sat(), 49_000);
}

#[test]
fn insufficient_funds_reports_both_sides() {
    // The one failure a caller can act on, so it names the numbers.
    match select_coins(&[utxo(1_000, 0)], 5_000).unwrap_err() {
        Error::InsufficientFunds {
            available,
            required,
        } => {
            assert_eq!(available, 1_000);
            assert_eq!(required, 5_000);
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
    assert!(matches!(
        select_coins(&[], 1).unwrap_err(),
        Error::InsufficientFunds { available: 0, .. }
    ));
}

#[test]
fn the_fee_is_exactly_inputs_minus_outputs() {
    // Bitcoin's fee is implicit, so this is the invariant that stops a
    // forgotten change output paying the balance to miners.
    let utxos = [utxo(100_000, 0)];
    let (tx, _) = transfer(30_000, 2_000).build(&utxos).unwrap();
    let out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(
        100_000 - out,
        2_000,
        "implicit fee must equal the stated fee"
    );
}

#[test]
fn every_input_is_signed_with_a_witness() {
    let utxos = [utxo(60_000, 0), utxo(60_000, 1)];
    let hex = transfer(100_000, 1_000).sign(&utxos, &key()).unwrap();
    assert_ne!(hex.len(), 0);
    // Segwit marker and flag follow the 4-byte version in the serialised
    // form: 02000000 then 0001.
    assert!(hex.starts_with("020000000001"), "{hex}");
}

#[test]
fn the_transaction_opts_into_replace_by_fee() {
    // A transfer stuck at a low fee should be bumpable rather than left
    // to sit in the mempool.
    let (tx, _) = transfer(10_000, 500).build(&[utxo(50_000, 0)]).unwrap();
    assert!(tx.input[0].sequence.is_rbf());
}

#[test]
fn a_key_that_does_not_control_the_sender_is_rejected() {
    let other = crate::key::derive(crate::Chain::Btc, VECTOR, "m/84'/0'/0'/0/1")
        .unwrap()
        .secret_bytes()
        .to_vec();
    match transfer(10_000, 500)
        .sign(&[utxo(50_000, 0)], &other)
        .unwrap_err()
    {
        Error::Signing { reason } => assert!(reason.contains("does not control")),
        other => panic!("expected Signing, got {other:?}"),
    }
}

#[test]
fn a_non_p2wpkh_sender_is_rejected() {
    // The signing path only implements P2WPKH; a legacy sender would fail
    // much later, after a transaction had been assembled.
    let legacy = Transfer {
        from: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        ..transfer(1_000, 100)
    };
    assert!(matches!(
        legacy.build(&[utxo(50_000, 0)]),
        Err(Error::Address(_))
    ));
}

#[test]
fn any_address_type_is_accepted_as_a_recipient() {
    // Paying to P2PKH, P2SH or P2TR is the same operation.
    for to in [
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    ] {
        let t = Transfer {
            to: to.to_string(),
            ..transfer(10_000, 500)
        };
        assert!(
            t.build(&[utxo(50_000, 0)]).is_ok(),
            "{to} should be payable"
        );
    }
}

#[test]
fn a_malformed_txid_is_rejected() {
    let bad = Utxo {
        txid: "not-a-txid".to_string(),
        vout: 0,
        value: 50_000,
    };
    match transfer(1_000, 100).build(&[bad]).unwrap_err() {
        Error::InvalidField { field, .. } => assert_eq!(field, "utxo.txid"),
        other => panic!("expected InvalidField, got {other:?}"),
    }
}

#[test]
fn signing_is_deterministic() {
    let utxos = [utxo(50_000, 0)];
    let t = transfer(10_000, 500);
    assert_eq!(
        t.sign(&utxos, &key()).unwrap(),
        t.sign(&utxos, &key()).unwrap()
    );
}

#[test]
fn changing_an_input_value_changes_the_signature() {
    // BIP-143 commits to each input's value, which is what stopped the
    // fee-inflation attack legacy sighash allowed.
    let t = transfer(10_000, 500);
    let a = t.sign(&[utxo(50_000, 0)], &key()).unwrap();
    let b = t.sign(&[utxo(60_000, 0)], &key()).unwrap();
    assert_ne!(a, b, "the input value must reach the sighash");
}

/// The compressed public key for the test mnemonic's P2WPKH account.
fn public_key() -> [u8; 33] {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    let secret = SecretKey::from_slice(&key()).unwrap();
    PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize()
}

#[test]
fn split_signing_matches_one_shot_signing_across_several_inputs() {
    // Several inputs on purpose: Bitcoin is the only chain here needing
    // more than one signature, and the split contract is that they come
    // back in input order. A transposition would still produce a
    // well-formed transaction — just an unspendable one — so the two
    // paths are compared byte-for-byte.
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    let utxos = [utxo(60_000, 0), utxo(70_000, 1), utxo(80_000, 2)];
    let transfer = transfer(150_000, 2_000);
    let public = public_key();

    let one_shot = transfer.sign(&utxos, &key()).unwrap();

    let (selection, digests) = transfer.sighashes(&utxos, &public).unwrap();
    assert!(
        digests.len() > 1,
        "the fixture must actually select several inputs"
    );
    assert_eq!(digests.len(), selection.inputs.len());

    let secret = SecretKey::from_slice(&key()).unwrap();
    let secp = Secp256k1::signing_only();
    let signatures: Vec<[u8; 64]> = digests
        .into_iter()
        .map(|digest| {
            secp.sign_ecdsa(&Message::from_digest(digest), &secret)
                .serialize_compact()
        })
        .collect();

    let split = transfer
        .attach_signatures(&utxos, &public, &signatures)
        .unwrap();

    assert_eq!(split, one_shot);
}

#[test]
fn a_public_key_that_does_not_control_the_sender_is_refused() {
    // Both halves must refuse, not just the first: a host could call
    // `attach_signatures` without ever calling `sighashes`.
    let utxos = [utxo(100_000, 0)];
    let transfer = transfer(50_000, 1_000);
    let wrong = [0x02u8; 33];

    assert!(matches!(
        transfer.sighashes(&utxos, &wrong),
        Err(Error::Signing { .. })
    ));
    assert!(matches!(
        transfer.attach_signatures(&utxos, &wrong, &[[0u8; 64]]),
        Err(Error::Signing { .. })
    ));
}

#[test]
fn a_signature_count_that_does_not_match_the_inputs_is_refused() {
    // Silently zipping would leave later inputs with an empty witness and
    // broadcast an unspendable transaction, paying the fee for nothing.
    let utxos = [utxo(60_000, 0), utxo(70_000, 1), utxo(80_000, 2)];
    let transfer = transfer(150_000, 2_000);

    let error = transfer
        .attach_signatures(&utxos, &public_key(), &[[0x11; 64]])
        .unwrap_err();
    assert!(matches!(error, Error::Signing { .. }), "{error:?}");
}

#[test]
fn a_utxo_total_that_overflows_is_an_invalid_field() {
    let half = u64::MAX / 2 + 1;
    let utxos = [utxo(half, 0), utxo(half, 1)];
    match select_coins(&utxos, u64::MAX).unwrap_err() {
        Error::InvalidField { field, .. } => assert_eq!(field, "utxos"),
        other => panic!("expected InvalidField, got {other:?}"),
    }
}

#[test]
fn an_amount_plus_fee_that_overflows_is_an_invalid_field() {
    match transfer(u64::MAX, 1).build(&[utxo(50_000, 0)]).unwrap_err() {
        Error::InvalidField { field, .. } => assert_eq!(field, "amount"),
        other => panic!("expected InvalidField, got {other:?}"),
    }
}

#[test]
fn an_invalid_recipient_is_an_address_error_on_every_entry_point() {
    let mut bad = transfer(1_000, 100);
    bad.to = "not-an-address".to_string();
    let utxos = [utxo(50_000, 0)];
    assert!(matches!(bad.build(&utxos), Err(Error::Address(_))));
    assert!(matches!(
        bad.attach_signatures(&utxos, &public_key(), &[[0x11; 64]]),
        Err(Error::Address(_))
    ));
}

#[test]
fn a_secret_key_of_the_wrong_length_is_a_signing_error() {
    let error = transfer(1_000, 100)
        .sign(&[utxo(50_000, 0)], &[0u8; 5])
        .unwrap_err();
    assert!(matches!(error, Error::Signing { .. }), "{error:?}");
}

#[test]
fn a_public_key_that_is_not_on_the_curve_is_refused() {
    let utxos = [utxo(50_000, 0)];
    let invalid = [0u8; 33];
    assert!(matches!(
        transfer(1_000, 100).sighashes(&utxos, &invalid),
        Err(Error::Signing { .. })
    ));
}

#[test]
fn a_signature_that_is_not_a_valid_pair_is_refused() {
    let utxos = [utxo(50_000, 0)];
    let error = transfer(1_000, 100)
        .attach_signatures(&utxos, &public_key(), &[[0xff; 64]])
        .unwrap_err();
    assert!(matches!(error, Error::Signing { .. }), "{error:?}");
}

#[test]
fn a_script_for_a_malformed_address_is_an_invalid_field() {
    match script_pubkey("garbage").unwrap_err() {
        Error::InvalidField { field, .. } => assert_eq!(field, "address"),
        other => panic!("expected InvalidField, got {other:?}"),
    }
}
