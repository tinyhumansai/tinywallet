//! End-to-end test for loading the built `TinyWallet` module into `TinyBus`.
//!
//! The only test that exercises the real thing: the built `cdylib`, the ABI
//! descriptor, manifest admission, the dynamic loader, and a broker routing
//! actual frames. Everything else in this crate calls Rust functions directly
//! and would keep passing if the artifact stopped loading altogether.
//!
//! What it proves that a unit test cannot: a transaction signed *through the
//! loaded module* is byte-for-byte the transaction the library produces signing
//! in one step. That is the whole claim of moving signing out of a host — if it
//! were false, the host would broadcast something other than what it built.
//!
//! It also demonstrates the property the design exists for: **no method call
//! below carries a private key.** The key never leaves this process, and the
//! module never sees one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use tinybus::Connection;
use tinybus::broker::Broker;
use tinybus::module::{ModuleHost, ModuleState};
use tinybus::transport::memory::MemoryBus;
use tinywallet::wire::{
    AttachRequest, PublicKey, Scheme, Signature, SignedTransaction, SigningRequest,
    TransactionSpec, UnsignedTransaction,
};
use tinywallet::{Chain, tx};
use tinywallet_module::{BUS_NAME, OBJECT_PATH};

/// Every method the manifest must declare, in order.
const EXPECTED_METHODS: &[&str] = &["BuildUnsigned", "AttachSignature"];

/// The BIP-39 test vector mnemonic. Never use it for real funds.
const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYWALLET_TEST_MODULE to point at the built cdylib"]
async fn the_built_module_signs_every_chain_over_a_real_broker() {
    // One test rather than four: TinyBus never unloads a module, and a second
    // load of the same artifact would collide on the well-known name, so every
    // chain is exercised against the one admitted instance.
    let (client, modules, broker_task) = admit_module();
    let client = client.await;
    wait_until_serving(&client).await;

    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME).unwrap();

    signs_an_evm_transfer_identically_to_the_library(&proxy).await;
    signs_a_multi_input_bitcoin_spend(&proxy).await;
    signs_a_solana_transfer(&proxy).await;
    refuses_a_request_the_module_cannot_build(&proxy).await;

    assert!(matches!(modules.list()[0].state, ModuleState::Ready));
    broker_task.abort();
}

/// Load the built artifact and check its manifest against the interface.
fn admit_module() -> (
    impl std::future::Future<Output = Connection>,
    ModuleHost,
    tokio::task::JoinHandle<tinybus::Result<()>>,
) {
    let artifact =
        std::env::var_os("TINYWALLET_TEST_MODULE").expect("TINYWALLET_TEST_MODULE must be set");
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);

    let loaded = modules.load_file(artifact).expect("module should load");
    assert_eq!(loaded.name, "tinywallet-module");
    assert_eq!(loaded.manifest.bus_name.as_str(), BUS_NAME);
    assert_eq!(loaded.manifest.object_path.as_str(), OBJECT_PATH);

    let declared: Vec<&str> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(
        declared, EXPECTED_METHODS,
        "manifest methods drifted from the interface"
    );

    let connect = async move {
        Connection::connect(bus.connect().await.unwrap())
            .await
            .unwrap()
    };
    (connect, modules, broker_task)
}

/// Wait for the module to claim its well-known name.
async fn wait_until_serving(client: &Connection) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .list_names()
                .await
                .unwrap()
                .iter()
                .any(|name| name.as_str() == BUS_NAME)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("module should become ready");
}

/// The load-bearing case: through the bus must equal in-process.
async fn signs_an_evm_transfer_identically_to_the_library(proxy: &tinybus::Proxy) {
    let secret = derive(Chain::Evm, "m/44'/60'/0'/0/0");
    let spec = TransactionSpec::Evm {
        to: "0x3535353535353535353535353535353535353535".to_string(),
        value_wei: "1000000000000000000".to_string(),
        data_hex: "0x".to_string(),
        nonce: 9,
        gas_limit: 21_000,
        gas_price_wei: "20000000000".to_string(),
        chain_id: 1,
    };

    let signed = round_trip(proxy, &spec, &secret).await;

    let expected = tx::evm::LegacyTransaction {
        nonce: 9,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: Some("0x3535353535353535353535353535353535353535".to_string()),
        value: 1_000_000_000_000_000_000,
        data: Vec::new(),
        chain_id: 1,
    }
    .sign(&secret)
    .unwrap();

    assert_eq!(
        signed.raw,
        format!("0x{}", hex(&expected)),
        "a transaction signed through the module diverged from the library"
    );
    assert_eq!(
        signed.txid,
        Some(tx::evm::LegacyTransaction::hash_of(&expected))
    );
}

/// Several inputs, so the multi-signature ordering crosses the bus for real.
async fn signs_a_multi_input_bitcoin_spend(proxy: &tinybus::Proxy) {
    let derived = tinywallet::key::derive(Chain::Btc, VECTOR, "m/84'/0'/0'/0/0").unwrap();
    let secret = derived.secret_bytes().to_vec();
    let txid = "7f3b662ea8b6ff2e0e1a1f9bd0f1c39a6b8ba51e1b0f0e0d0c0b0a0908070605";
    let spec = TransactionSpec::Btc {
        from: derived.address().to_string(),
        to: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        amount_sat: 150_000,
        fee_sat: 2_000,
        utxos: (0..3)
            .map(|vout| tinywallet::wire::Utxo {
                txid: txid.to_string(),
                vout,
                value: 60_000 + u64::from(vout) * 10_000,
            })
            .collect(),
    };

    let signed = round_trip(proxy, &spec, &secret).await;

    let expected = tx::btc::Transfer {
        from: derived.address().to_string(),
        to: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        amount: 150_000,
        fee: 2_000,
    }
    .sign(
        &(0..3)
            .map(|vout| tx::btc::Utxo {
                txid: txid.to_string(),
                vout,
                value: 60_000 + u64::from(vout) * 10_000,
            })
            .collect::<Vec<_>>(),
        &secret,
    )
    .unwrap();

    assert_eq!(signed.raw, expected);
}

/// ed25519 rather than a prehashed digest, so the other signing scheme is covered.
async fn signs_a_solana_transfer(proxy: &tinybus::Proxy) {
    use ed25519_dalek::{Signer as _, SigningKey};

    let derived = tinywallet::key::derive(Chain::Solana, VECTOR, "m/44'/501'/0'/0'").unwrap();
    let spec = TransactionSpec::Solana {
        from: derived.address().to_string(),
        to: "11111111111111111111111111111111".to_string(),
        lamports: 1_000_000_000,
        recent_blockhash: "11111111111111111111111111111111".to_string(),
    };
    let public = PublicKey {
        key_hex: hex(derived.secret_bytes()),
    };

    let unsigned: UnsignedTransaction = proxy
        .call(
            "BuildUnsigned",
            (SigningRequest {
                transaction: spec.clone(),
                public_key: public.clone(),
            },),
        )
        .await
        .unwrap();
    assert_eq!(unsigned.payloads[0].scheme, Scheme::Ed25519);

    // Signed here, in this process. The module is never given the key.
    let key: [u8; 32] = derived.secret_bytes().try_into().unwrap();
    let signature = SigningKey::from_bytes(&key)
        .sign(&unhex(&unsigned.payloads[0].bytes_hex))
        .to_bytes();

    let signed: SignedTransaction = proxy
        .call(
            "AttachSignature",
            (AttachRequest {
                transaction: spec.clone(),
                public_key: public,
                signatures: vec![Signature::Ed25519 {
                    signature_hex: hex(&signature),
                }],
            },),
        )
        .await
        .unwrap();

    let expected = tx::solana::NativeTransfer {
        from: derived.address().to_string(),
        to: "11111111111111111111111111111111".to_string(),
        lamports: 1_000_000_000,
        recent_blockhash: "11111111111111111111111111111111".to_string(),
    }
    .sign(derived.secret_bytes())
    .unwrap();

    assert_eq!(signed.raw, base64(&expected));
}

/// A malformed request must come back as a named error, not a signature.
///
/// This used to send a request whose `chain` tag contradicted its transaction.
/// That is no longer expressible — the requests carry no `chain` and the spec
/// names its own — so the case is now a transaction the module can parse but
/// cannot build: a Tron payload whose recomputed `txID` disagrees with the one
/// claimed, which is the defence against a compromised node.
async fn refuses_a_request_the_module_cannot_build(proxy: &tinybus::Proxy) {
    let result: tinybus::Result<UnsignedTransaction> = proxy
        .call(
            "BuildUnsigned",
            (SigningRequest {
                transaction: TransactionSpec::Tron {
                    raw_data_hex: "0a02b1f12208".to_string() + &"ab".repeat(64),
                    expected_to: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".to_string(),
                    expected_txid: "00".repeat(32),
                },
                public_key: PublicKey {
                    key_hex: "02".repeat(33),
                },
            },),
        )
        .await;

    let error = result.expect_err("a tampered transaction must not produce a signature");
    assert_eq!(
        error.wire_name(),
        "ai.tinyhumans.tinywallet.Error.InvalidInput",
        "the wire error name is the contract a host matches on"
    );
}

/// Drive both calls for a secp256k1 chain, signing locally in between.
async fn round_trip(
    proxy: &tinybus::Proxy,
    spec: &TransactionSpec,
    secret: &[u8],
) -> SignedTransaction {
    let public_key = PublicKey {
        key_hex: hex(&compressed_public(secret)),
    };

    let unsigned: UnsignedTransaction = proxy
        .call(
            "BuildUnsigned",
            (SigningRequest {
                transaction: spec.clone(),
                public_key: public_key.clone(),
            },),
        )
        .await
        .unwrap();

    // Every payload signed here, with a key the module has never seen.
    let signatures = unsigned
        .payloads
        .iter()
        .map(|payload| {
            assert_eq!(payload.scheme, Scheme::Secp256k1Prehash);
            let digest: [u8; 32] = unhex(&payload.bytes_hex).try_into().unwrap();
            let secret = SecretKey::from_slice(secret).unwrap();
            let recoverable = Secp256k1::signing_only()
                .sign_ecdsa_recoverable(&Message::from_digest(digest), &secret);
            let (recovery_id, compact) = recoverable.serialize_compact();
            Signature::Secp256k1 {
                rs_hex: hex(&compact),
                recovery_id: u8::try_from(recovery_id.to_i32()).unwrap(),
            }
        })
        .collect();

    proxy
        .call(
            "AttachSignature",
            (AttachRequest {
                transaction: spec.clone(),
                public_key,
                signatures,
            },),
        )
        .await
        .unwrap()
}

fn derive(chain: Chain, path: &str) -> Vec<u8> {
    tinywallet::key::derive(chain, VECTOR, path)
        .unwrap()
        .secret_bytes()
        .to_vec()
}

fn compressed_public(secret: &[u8]) -> [u8; 33] {
    use bitcoin::secp256k1::PublicKey as SecpPublic;
    let secret = SecretKey::from_slice(secret).unwrap();
    SecpPublic::from_secret_key(&Secp256k1::new(), &secret).serialize()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

/// Standard base64, matching what the module emits for Solana.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(TABLE[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((triple >> 12) & 0x3f) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(TABLE[((triple >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(TABLE[(triple & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}
