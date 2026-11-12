//! Tests for `X402SignIn`: the module signs a `sign-in-with-x` challenge with
//! the EVM secret it is handed, and refuses anything else.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::service::x402::tests::secret;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tinywallet_bus::wire::X402SignInRequest;

const URL: &str = "https://wallet.fixture.test/api/x-accounts/start";

/// A live-shaped challenge for the fixture origin, valid for five minutes.
fn challenge(domain: &str) -> String {
    let now = chrono::Utc::now();
    BASE64.encode(
        serde_json::to_vec(&serde_json::json!({
            "x402Version": 2,
            "error": "SIWX authentication required",
            "resource": {"url": URL},
            "accepts": [],
            "extensions": {"sign-in-with-x": {
                "info": {
                    "domain": domain,
                    "uri": URL,
                    "version": "1",
                    "nonce": "c3dae5e13c973fa183371bf7fa769206",
                    "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "expirationTime": (now + chrono::Duration::minutes(5))
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "statement": "Sign in to connect an account",
                    "resources": [URL]
                },
                "supportedChains": [{"chainId": "eip155:8453", "type": "eip191"}]
            }}
        }))
        .unwrap(),
    )
}

fn request(payment_required: String, chain: tinywallet_bus::Chain) -> X402SignInRequest {
    X402SignInRequest {
        url: URL.to_string(),
        payment_required,
        secret: secret(chain),
    }
}

#[tokio::test]
async fn the_evm_account_signs_a_challenge_for_the_requested_host() {
    let response = sign_in(request(
        challenge("wallet.fixture.test"),
        tinywallet_bus::Chain::Evm,
    ))
    .await
    .unwrap();
    assert_eq!(
        response.address,
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
    assert_eq!(response.chain_id, "eip155:8453");
    let payload: serde_json::Value =
        serde_json::from_slice(&BASE64.decode(&response.header).unwrap()).unwrap();
    assert_eq!(payload["address"], response.address);
    assert_eq!(payload["domain"], "wallet.fixture.test");
    assert_eq!(payload["type"], "eip191");
    // `0x` + r ‖ s ‖ v.
    assert_eq!(payload["signature"].as_str().unwrap().len(), 132);
}

#[tokio::test]
async fn a_challenge_for_another_host_is_refused() {
    let error = sign_in(request(
        challenge("evil.example"),
        tinywallet_bus::Chain::Evm,
    ))
    .await
    .unwrap_err();
    assert!(error.contains("sign-in-with-x refused"), "{error}");
}

#[tokio::test]
async fn only_an_evm_secret_signs_in() {
    let error = sign_in(request(
        challenge("wallet.fixture.test"),
        tinywallet_bus::Chain::Solana,
    ))
    .await
    .unwrap_err();
    assert!(error.contains("EVM"), "{error}");
}

#[tokio::test]
async fn an_unreadable_challenge_is_refused() {
    let error = sign_in(request("not base64!".into(), tinywallet_bus::Chain::Evm))
        .await
        .unwrap_err();
    assert!(error.contains("challenge"), "{error}");
}
