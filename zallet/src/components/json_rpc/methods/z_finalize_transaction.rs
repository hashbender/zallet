use std::sync::{Arc, LazyLock};

use bip32::ChildNumber;
use jsonrpsee::core::{JsonValue, RpcResult};
use pczt::{
    Pczt,
    roles::{
        prover::Prover,
        signer::{self, Signer},
        updater::Updater,
    },
};
use secrecy::ExposeSecret;
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zcash_client_backend::data_api::{
    Account, WalletRead, wallet::extract_and_store_transaction_from_pczt,
};
use zcash_client_sqlite::ReceivedNoteId;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::NetworkConstants;
use zip32::fingerprint::SeedFingerprint;

use crate::components::{
    chain::Chain,
    database::DbHandle,
    json_rpc::{
        payments::{
            SendResult, broadcast_transactions, cached_required_policy, parse_privacy_policy,
            pczt_policy_key,
        },
        server::LegacyCode,
        utils::parse_account_parameter,
    },
    keystore::KeyStore,
};
use crate::config::ZalletConfig;

/// The Orchard proving and verifying keys are deterministic and expensive to build (each
/// takes on the order of seconds), so build them once and reuse them across requests.
static ORCHARD_PROVING_KEY: LazyLock<orchard::circuit::ProvingKey> =
    LazyLock::new(orchard::circuit::ProvingKey::build);
static ORCHARD_VERIFYING_KEY: LazyLock<orchard::circuit::VerifyingKey> =
    LazyLock::new(orchard::circuit::VerifyingKey::build);

/// Response to a `z_finalizetransaction` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The result of a `z_finalizetransaction` request: the resulting transaction ID(s).
pub(crate) type ResultType = SendResult;

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "The UUID of the account whose keys should sign the transaction.";
pub(super) const PARAM_PCZT_DESC: &str =
    "The hex-encoded PCZT to finalize, as returned by z_proposetransaction.";
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str = "Policy for what information leakage is acceptable, acknowledging the transaction's privacy \
     implications.";

pub(crate) async fn call<C: Chain>(
    config: Arc<ZalletConfig>,
    wallet: DbHandle,
    keystore: KeyStore,
    chain: C,
    account: JsonValue,
    pczt: String,
    privacy_policy: String,
) -> Response {
    let privacy_policy = parse_privacy_policy(Some(&privacy_policy))?;

    let pczt = decode_pczt(&pczt)?;

    // If this PCZT was proposed by this node, `z_proposetransaction` recorded the policy it
    // requires (computed exactly from the proposal). Enforce that the caller acknowledged a
    // sufficient policy. On a cache miss (eviction, restart, or a PCZT proposed elsewhere) we
    // cannot re-derive the requirement reliably, so the supplied policy is accepted as
    // acknowledgement only. https://github.com/zcash/wallet/issues/217
    if let Some(required) = cached_required_policy(&pczt_policy_key(&pczt.serialize())) {
        if !privacy_policy.is_compatible_with(required) {
            return Err(LegacyCode::InvalidParameter.with_message(format!(
                "The privacy policy {privacy_policy} does not permit this transaction, which \
                 requires at least {required}."
            )));
        }
    }

    let account_id = parse_account_parameter(wallet.as_ref(), &keystore, &account).await?;

    let account = wallet
        .as_ref()
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| {
            LegacyCode::InvalidParameter
                .with_message(format!("No account with UUID {}", account_id.expose_uuid()))
        })?;

    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey
            .with_static("Cannot sign for an account that has no spending key.")
    })?;

    // The seed fingerprint and coin type identify which transparent inputs belong to this
    // account, so that the correct key can be derived for each.
    let seed_fp = *derivation.seed_fingerprint();
    let coin_type = ChildNumber::new(wallet.params().coin_type(), true)
        .map_err(|e| LegacyCode::Wallet.with_message(format!("Invalid coin type: {e}")))?;

    let seed = keystore
        .decrypt_seed(derivation.seed_fingerprint())
        .await
        .map_err(|e| match e.kind() {
            crate::error::ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
            }
            _ => LegacyCode::Database.with_message(e.to_string()),
        })?;
    let usk = UnifiedSpendingKey::from_seed(
        wallet.params(),
        seed.expose_secret(),
        derivation.account_index(),
    )
    .map_err(|e| LegacyCode::InvalidAddressOrKey.with_message(e.to_string()))?;

    // Proving, signing, and proof verification are CPU-bound; run them on the blocking pool.
    let (wallet, txid) = crate::spawn_blocking!("z_finalizetransaction prover", move || {
        let pczt = authorize_pczt(pczt, &usk, &seed_fp, coin_type)?;

        let prover = LocalTxProver::bundled();
        let (spend_vk, output_vk) = prover.verifying_keys();

        let mut wallet = wallet;
        let txid = extract_and_store_transaction_from_pczt::<_, ReceivedNoteId>(
            wallet.as_mut(),
            pczt,
            Some((&spend_vk, &output_vk)),
            Some(&ORCHARD_VERIFYING_KEY),
        )
        .map_err(|e| {
            LegacyCode::Wallet.with_message(format!("Failed to extract transaction from PCZT: {e}"))
        })?;

        Ok::<_, jsonrpsee::types::ErrorObjectOwned>((wallet, txid))
    })
    .await
    .map_err(|e| {
        LegacyCode::Wallet.with_message(format!("PCZT finalization task panicked: {e}"))
    })??;

    broadcast_transactions(&config, &wallet, chain, vec![txid]).await
}

/// Decodes the hex-encoded PCZT argument into a [`Pczt`], mapping malformed input to a
/// JSON-RPC invalid-parameter error.
fn decode_pczt(pczt: &str) -> RpcResult<Pczt> {
    let bytes = hex::decode(pczt.trim())
        .map_err(|e| LegacyCode::InvalidParameter.with_message(format!("Invalid PCZT hex: {e}")))?;
    Pczt::parse(&bytes)
        .map_err(|e| LegacyCode::InvalidParameter.with_message(format!("Invalid PCZT: {e:?}")))
}

/// Adds proof generation keys, creates proofs, and applies this account's spend authorizing
/// signatures to a PCZT, returning the fully-authorized PCZT ready for extraction.
///
/// Handles Sapling, Orchard, and transparent inputs. For the shielded pools the spend
/// metadata does not say which spends belong to this account, so each candidate signature is
/// attempted and wrong-key errors are ignored, matching the reference driver in
/// `zcash_client_backend`. Transparent inputs are matched to this account by their BIP 44
/// derivation (seed fingerprint and coin type), and the corresponding key is derived to sign.
fn authorize_pczt(
    pczt: Pczt,
    usk: &UnifiedSpendingKey,
    seed_fp: &SeedFingerprint,
    coin_type: ChildNumber,
) -> RpcResult<Pczt> {
    let sapling_extsk = usk.sapling();

    // 1. Add Sapling proof generation keys to the account's (non-dummy) spends (Orchard has
    //    no equivalent step), and identify the transparent inputs belonging to this account
    //    by their BIP 44 derivation so they can be signed below.
    let mut transparent_inputs: Vec<(usize, TransparentKeyScope, NonHardenedChildIndex)> = vec![];
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            let spends_without_pgk = updater
                .bundle()
                .spends()
                .iter()
                .enumerate()
                .filter_map(|(index, spend)| {
                    spend.proof_generation_key().is_none().then_some(index)
                })
                .collect::<Vec<_>>();

            for index in spends_without_pgk {
                updater.update_spend_with(index, |mut spend_updater| {
                    spend_updater
                        .set_proof_generation_key(sapling_extsk.expsk.proof_generation_key())
                })?;
            }

            Ok(())
        })
        .map_err(|e| {
            LegacyCode::Wallet.with_message(format!(
                "Failed to update PCZT with proof generation keys: {e:?}"
            ))
        })?
        .update_transparent_with(|updater| {
            for (index, input) in updater.bundle().inputs().iter().enumerate() {
                for derivation in input.bip32_derivation().values() {
                    if let Some((_account, scope, address_index)) =
                        derivation.extract_bip_44_fields(seed_fp, coin_type)
                    {
                        transparent_inputs.push((index, scope, address_index));
                        break;
                    }
                }
            }
            Ok(())
        })
        .map_err(|e| {
            LegacyCode::Wallet.with_message(format!("Failed to read transparent inputs: {e:?}"))
        })?
        .finish();

    // 2. Create proofs, building each (expensive) proving key only when the PCZT needs it.
    let prover = Prover::new(pczt);
    let prover = if prover.requires_sapling_proofs() {
        let sapling_prover = LocalTxProver::bundled();
        prover
            .create_sapling_proofs(&sapling_prover, &sapling_prover)
            .map_err(|e| {
                LegacyCode::Wallet.with_message(format!("Failed to create Sapling proofs: {e:?}"))
            })?
    } else {
        prover
    };
    let prover = if prover.requires_orchard_proof() {
        prover
            .create_orchard_proof(&ORCHARD_PROVING_KEY)
            .map_err(|e| {
                LegacyCode::Wallet.with_message(format!("Failed to create Orchard proof: {e:?}"))
            })?
    } else {
        prover
    };
    let pczt = prover.finish();

    // 3. Derive the signing key for each transparent input identified above.
    let mut transparent_keys = vec![];
    for (index, scope, address_index) in transparent_inputs {
        let sk = usk
            .transparent()
            .derive_secret_key(scope, address_index)
            .map_err(|e| {
                LegacyCode::Wallet.with_message(format!("Failed to derive transparent key: {e}"))
            })?;
        transparent_keys.push((index, sk));
    }

    // 4. Apply spend authorizing signatures for both shielded pools and the transparent
    //    inputs.
    let mut signer = Signer::new(pczt).map_err(|e| {
        LegacyCode::Wallet.with_message(format!("Failed to start PCZT signer: {e:?}"))
    })?;

    let sapling_ask = &sapling_extsk.expsk.ask;
    for index in 0.. {
        match signer.sign_sapling(index, sapling_ask) {
            Err(signer::Error::InvalidIndex) => break,
            Ok(())
            | Err(signer::Error::SaplingSign(
                sapling::pczt::SignerError::WrongSpendAuthorizingKey,
            )) => {}
            Err(e) => {
                return Err(LegacyCode::Wallet
                    .with_message(format!("Failed to apply Sapling signature: {e:?}")));
            }
        }
    }

    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    for index in 0.. {
        match signer.sign_orchard(index, &orchard_ask) {
            Err(signer::Error::InvalidIndex) => break,
            Ok(())
            | Err(signer::Error::OrchardSign(
                orchard::pczt::SignerError::WrongSpendAuthorizingKey,
            )) => {}
            Err(e) => {
                return Err(LegacyCode::Wallet
                    .with_message(format!("Failed to apply Orchard signature: {e:?}")));
            }
        }
    }

    for (index, sk) in &transparent_keys {
        signer.sign_transparent(*index, sk).map_err(|e| {
            LegacyCode::Wallet.with_message(format!("Failed to apply transparent signature: {e:?}"))
        })?;
    }

    Ok(signer.finish())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn rejects_non_hex_input() {
        let err = decode_pczt("nothex").expect_err("non-hex PCZT should be rejected");
        assert!(
            err.message().starts_with("Invalid PCZT hex:"),
            "unexpected message: {}",
            err.message(),
        );
    }

    #[test]
    fn rejects_valid_hex_that_is_not_a_pczt() {
        // Valid hex, but not a PCZT (wrong magic bytes / structure).
        let err = decode_pczt("00010203").expect_err("non-PCZT bytes should be rejected");
        assert!(
            err.message().starts_with("Invalid PCZT:"),
            "unexpected message: {}",
            err.message(),
        );
    }

    #[test]
    fn ignores_surrounding_whitespace() {
        // Whitespace is trimmed before decoding, so the error is about the PCZT contents,
        // not the hex.
        let err = decode_pczt("  00  ").expect_err("non-PCZT bytes should be rejected");
        assert!(err.message().starts_with("Invalid PCZT:"));
    }

    proptest! {
        /// Decoding never panics, whatever the caller passes.
        #[test]
        fn never_panics_on_arbitrary_strings(s in ".*") {
            let _ = decode_pczt(&s);
        }

        /// Arbitrary well-formed hex that is not a real PCZT is rejected cleanly (never
        /// parses, never panics).
        #[test]
        fn rejects_arbitrary_hex_bytes(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let err = decode_pczt(&hex::encode(&bytes))
                .expect_err("random bytes are not a valid PCZT");
            prop_assert!(err.message().starts_with("Invalid PCZT:"));
        }
    }
}

/// End-to-end coverage of the finalize pipeline against a real funded wallet: a transaction
/// is proposed, turned into a PCZT, authorized by [`authorize_pczt`] (proof generation keys,
/// proofs, and signatures), and extracted into a valid transaction. This mirrors the
/// librustzcash `pczt_single_step` reference flow with zallet's signing spliced in, and is the
/// "whole process" test for `z_proposetransaction` + `z_finalizetransaction`.
#[cfg(test)]
mod round_trip_tests {
    use std::convert::Infallible;

    use incrementalmerkletree::frontier::Frontier;
    use secrecy::ExposeSecret;
    use zcash_client_backend::zip321::{Payment, TransactionRequest};
    use zcash_client_backend::{
        data_api::{
            Account as _, WalletRead,
            chain::ChainState,
            testing::{
                AddressType, InitialChainState, TestBuilder, pool::ShieldedPoolTester,
                sapling::SaplingPoolTester, single_output_change_strategy,
            },
            wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        },
        fees::StandardFeeRule,
        wallet::OvkPolicy,
    };
    use zcash_client_sqlite::testing::{BlockCache, db::TestDbFactory};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{
        ShieldedProtocol,
        consensus::{NetworkUpgrade, Parameters, ZIP212_GRACE_PERIOD},
        value::Zatoshis,
    };

    use super::*;

    /// Drives the full finalize round trip for a Sapling-funded account: authorize_pczt must
    /// produce a PCZT that extracts into a transaction the wallet stores.
    #[test]
    fn sapling_round_trip_produces_a_stored_transaction() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_initial_chain_state(|_, network| {
                // Start after ZIP 212 enforcement so the PCZT can be extracted.
                let birthday_height = std::cmp::max(
                    network.activation_height(NetworkUpgrade::Nu5).unwrap(),
                    network.activation_height(NetworkUpgrade::Canopy).unwrap()
                        + ZIP212_GRACE_PERIOD,
                );
                InitialChainState {
                    chain_state: ChainState::new(
                        birthday_height - 1,
                        BlockHash([5; 32]),
                        Frontier::empty(),
                        Frontier::empty(),
                    ),
                    prior_sapling_roots: vec![],
                    prior_orchard_roots: vec![],
                }
            })
            .with_account_having_current_birthday()
            .build();

        let account = st.test_account().cloned().unwrap();
        let fvk = SaplingPoolTester::test_account_fvk(&st);

        // Fund the account with a single Sapling note.
        let note_value = Zatoshis::const_from_u64(350_000);
        st.generate_next_block(&fvk, AddressType::DefaultExternal, note_value);
        st.scan_cached_blocks(account.birthday().height(), 1);
        assert_eq!(st.get_total_balance(account.id()), note_value);

        // Propose a transfer back to the account's own Sapling address.
        let to = SaplingPoolTester::fvk_default_address(&fvk);
        let request = TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(200_000),
        )])
        .unwrap();

        let input_selector = GreedyInputSelector::new();
        let change_strategy =
            single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedProtocol::Sapling);
        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let pczt = st
            .create_pczt_from_proposal::<Infallible, _, Infallible>(
                account.id(),
                OvkPolicy::Sender,
                &proposal,
            )
            .unwrap();

        // The code under test: zallet's authorize_pczt.
        let seed_fp = SeedFingerprint::from_seed(st.test_seed().unwrap().expose_secret())
            .expect("test seed has a valid length");
        let coin_type = ChildNumber::new(st.network().coin_type(), true).unwrap();
        let authorized =
            authorize_pczt(pczt, account.usk(), &seed_fp, coin_type).expect("authorize succeeds");

        // Round-trip through hex so decode_pczt is exercised on a valid PCZT too.
        let reparsed =
            decode_pczt(&hex::encode(authorized.serialize())).expect("re-decode succeeds");

        // An unsigned PCZT would fail here, so a successful extraction proves the signatures
        // and proofs are valid.
        let txid = st
            .extract_and_store_transaction_from_pczt(reparsed)
            .expect("extraction succeeds");

        assert!(
            st.wallet().get_transaction(txid).unwrap().is_some(),
            "the finalized transaction should be stored in the wallet",
        );
    }
}
