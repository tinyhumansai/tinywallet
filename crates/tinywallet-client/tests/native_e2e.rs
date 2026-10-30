//! Real cached-module E2E tests for `TinyWalletClient` confidential wrappers.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[expect(
    dead_code,
    reason = "this fixture module is shared by independent Cargo integration-test crates"
)]
mod support;

use tinywallet_client::{
    Chain, ClientError, Scheme, SecretMaterial, Signature, TransactionSpec, methods,
};
use zeroize::Zeroize;

fn secret() -> SecretMaterial {
    SecretMaterial {
        mnemonic: support::VECTOR.to_string(),
        derivation_path: "m/44'/60'/0'/0/0".to_string(),
        chain: Chain::Evm,
    }
}

fn transaction() -> TransactionSpec {
    TransactionSpec::Evm {
        to: "0x3535353535353535353535353535353535353535".to_string(),
        value_wei: "1000000000000000000".to_string(),
        data_hex: "0x".to_string(),
        nonce: 9,
        gas_limit: 21_000,
        gas_price_wei: "20000000000".to_string(),
        chain_id: 1,
    }
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(TABLE[usize::from(byte >> 4)]));
        output.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    output
}

async fn assert_same_peer(fixture: &support::Fixture, expected: &tinybus::BusName) {
    assert_eq!(&fixture.access.unique_peer().await, expected);
}

#[tokio::test]
async fn all_six_confidential_wrappers_use_the_verified_unique_peer() {
    let fixture = support::fixture().await;
    let record = support::record(false);
    let unique_peer = fixture.access.unique_peer().await;
    let attestation = fixture.access.attestation().await;
    assert_eq!(attestation.name.as_str(), record.bus_name);
    assert_eq!(attestation.sha256, record.assets[0].sha256);
    assert_eq!(
        attestation.library_sha256.as_deref(),
        record.assets[0].library_sha256
    );

    let account = fixture
        .wallet
        .derive_account(secret())
        .await
        .expect("DeriveAccount returns its typed public account response");
    assert!(account.address.starts_with("0x"));
    assert_eq!(account.public_key.key_hex.len(), 66);
    assert_same_peer(&fixture, &unique_peer).await;

    let signed = fixture
        .wallet
        .sign_transaction(secret(), transaction())
        .await
        .expect("SignTransaction returns a module-signed transaction");
    assert!(signed.raw.starts_with("0x"));
    assert!(signed.raw.len() > 100);
    assert_same_peer(&fixture, &unique_peer).await;

    let signature = fixture
        .wallet
        .sign_message(secret(), &[0x42; 32], Scheme::Secp256k1Prehash)
        .await
        .expect("SignMessage returns its typed signature");
    assert!(matches!(
        signature,
        Signature::Secp256k1 { ref rs_hex, recovery_id }
            if rs_hex.len() == 128 && recovery_id <= 3
    ));
    assert_same_peer(&fixture, &unique_peer).await;

    let mut exported = fixture
        .wallet
        .export_key(secret())
        .await
        .expect("ExportKey returns its typed response only over attested delivery");
    assert_eq!(exported.secret_key_hex.len(), 64);
    assert_eq!(exported.address, account.address);
    exported.secret_key_hex.zeroize();
    assert_same_peer(&fixture, &unique_peer).await;

    let mut generated = fixture
        .wallet
        .generate_mnemonic(12)
        .await
        .expect("GenerateMnemonic returns its typed response");
    assert_eq!(generated.word_count, 12);
    assert_eq!(generated.phrase.split_whitespace().count(), 12);
    generated.phrase.zeroize();
    assert_same_peer(&fixture, &unique_peer).await;

    let mut seed = fixture
        .wallet
        .derive_mnemonic_seed(support::VECTOR.to_string())
        .await
        .expect("DeriveMnemonicSeed returns its typed response");
    assert!(
        hex(&seed.seed)
            == "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        "seed response must match the standard BIP-39 vector"
    );
    seed.seed.zeroize();
    assert_same_peer(&fixture, &unique_peer).await;
}

#[tokio::test]
async fn wrong_library_pin_prevents_business_delivery_for_all_confidential_methods() {
    let fixture = support::fixture().await;
    let unique_peer = fixture.access.unique_peer().await;

    assert!(support::expected_module_unavailable(
        fixture
            .wrong_pin_wallet
            .derive_account(secret())
            .await
            .unwrap_err()
    ));
    assert_same_peer(&fixture, &unique_peer).await;
    assert!(support::expected_module_unavailable(
        fixture
            .wrong_pin_wallet
            .sign_transaction(secret(), transaction())
            .await
            .unwrap_err()
    ));
    assert_same_peer(&fixture, &unique_peer).await;
    assert!(support::expected_module_unavailable(
        fixture
            .wrong_pin_wallet
            .sign_message(secret(), &[0x42; 32], Scheme::Secp256k1Prehash)
            .await
            .unwrap_err()
    ));
    assert_same_peer(&fixture, &unique_peer).await;
    assert!(support::expected_module_unavailable(
        fixture
            .wrong_pin_wallet
            .export_key(secret())
            .await
            .unwrap_err()
    ));
    assert_same_peer(&fixture, &unique_peer).await;
    assert!(support::expected_module_unavailable(
        fixture
            .wrong_pin_wallet
            .generate_mnemonic(12)
            .await
            .unwrap_err()
    ));
    assert_same_peer(&fixture, &unique_peer).await;
    assert!(support::expected_module_unavailable(
        fixture
            .wrong_pin_wallet
            .derive_mnemonic_seed(support::VECTOR.to_string())
            .await
            .unwrap_err()
    ));
    assert_same_peer(&fixture, &unique_peer).await;
}

#[tokio::test]
async fn ordinary_public_call_encodes_transfers_and_keeps_preflight_errors_safe() {
    let fixture = support::fixture().await;
    assert_eq!(format!("{:?}", fixture.wallet), "WalletClient { .. }");

    let calldata = fixture
        .wallet
        .encode_erc20_transfer(
            "0x1111111111111111111111111111111111111111".to_string(),
            "1".to_string(),
        )
        .await
        .expect("public ERC-20 encoding uses the actual module client");
    assert_eq!(
        calldata,
        "0xa9059cbb\
         0000000000000000000000001111111111111111111111111111111111111111\
         0000000000000000000000000000000000000000000000000000000000000001"
    );

    let confidential_request = serde_json::json!({});
    let confidential_error = fixture
        .wallet
        .call::<_, serde_json::Value>(methods::SIGN_MESSAGE, &confidential_request)
        .await
        .unwrap_err();
    assert!(matches!(
        &confidential_error,
        ClientError::ConfidentialRequired
    ));
    assert_eq!(
        confidential_error.to_string(),
        "wallet member requires attested delivery"
    );

    let public_request = serde_json::json!({});
    let public_error = fixture
        .wallet
        .call_attested::<_, serde_json::Value>(methods::ENCODE_ERC20_TRANSFER, &public_request)
        .await
        .unwrap_err();
    assert!(matches!(&public_error, ClientError::NotConfidential));
    assert_eq!(
        public_error.to_string(),
        "wallet member is not confidential"
    );

    let remote_error = fixture
        .wallet
        .encode_erc20_transfer("not-an-address".to_string(), "1".to_string())
        .await
        .unwrap_err();
    assert!(matches!(
        remote_error,
        ClientError::Remote(failure)
            if failure.wire_name == "ai.tinyhumans.tinywallet.Error.InvalidInput"
    ));
}
