//! A separate-process test for refusing secrets to an unattested module peer.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[expect(
    dead_code,
    reason = "this fixture module is shared by independent Cargo integration-test crates"
)]
mod support;

use tinywallet_client::{Chain, Scheme, SecretMaterial, TransactionSpec};

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

#[tokio::test]
async fn unattested_module_never_receives_any_confidential_wrapper_request() {
    let fixture = support::unattested_fixture().await;
    assert!(fixture.access.observed_attestation().await.is_none());

    assert!(support::expected_module_unavailable(
        fixture.wallet.derive_account(secret()).await.unwrap_err()
    ));
    assert!(support::expected_module_unavailable(
        fixture
            .wallet
            .sign_transaction(secret(), transaction())
            .await
            .unwrap_err()
    ));
    assert!(support::expected_module_unavailable(
        fixture
            .wallet
            .sign_message(secret(), &[0x42; 32], Scheme::Secp256k1Prehash)
            .await
            .unwrap_err()
    ));
    assert!(support::expected_module_unavailable(
        fixture.wallet.export_key(secret()).await.unwrap_err()
    ));
    assert!(support::expected_module_unavailable(
        fixture.wallet.generate_mnemonic(12).await.unwrap_err()
    ));
    assert!(support::expected_module_unavailable(
        fixture
            .wallet
            .derive_mnemonic_seed(support::VECTOR.to_string())
            .await
            .unwrap_err()
    ));
}
