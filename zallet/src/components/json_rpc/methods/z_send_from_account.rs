use std::convert::Infallible;
use std::num::NonZeroU32;

use jsonrpsee::core::{JsonValue, RpcResult};
use secrecy::ExposeSecret;
use zcash_client_backend::{
    data_api::{
        Account, WalletRead,
        wallet::{
            ConfirmationsPolicy, SpendingKeys, input_selection::GreedyInputSelector,
            propose_transfer,
        },
    },
    fees::{DustOutputPolicy, StandardFeeRule, standard::MultiOutputChangeStrategy},
};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::ShieldedProtocol;

use std::sync::Arc;

use crate::{
    components::{
        chain::Chain,
        database::DbHandle,
        json_rpc::{
            fund_source::{FundSource, FundSourceFilter},
            methods::z_send_many::{build_request, check_orchard_actions_limit, run},
            payments::{AmountParameter, SendResult, enforce_privacy_policy, parse_privacy_policy},
            server::LegacyCode,
            utils::parse_account_parameter,
        },
        keystore::KeyStore,
    },
    config::ZalletConfig,
};

#[cfg(feature = "zcashd-import")]
use crate::components::json_rpc::utils::collect_standalone_transparent_keys;

/// Response to a `z_sendfromaccount` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The result of a `z_sendfromaccount` request: the resulting transaction ID(s).
pub(crate) type ResultType = SendResult;

pub(super) const PARAM_ACCOUNT_DESC: &str = "The UUID of the account to send the funds from.";
pub(super) const PARAM_FUND_SOURCE_DESC: &str = "Where funds may be drawn from: \"orchard\", \"sapling\", \"any_transparent\", or an array \
     of transparent addresses.";
pub(super) const PARAM_RECIPIENTS_DESC: &str =
    "An array of JSON objects representing the amounts to send.";
pub(super) const PARAM_RECIPIENTS_REQUIRED: bool = true;
pub(super) const PARAM_MINCONF_DESC: &str = "Only use funds confirmed at least this many times.";
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str = "Policy for what information leakage is acceptable, acknowledging the transaction's privacy \
     implications.";

#[allow(clippy::too_many_arguments)]
pub(crate) async fn call<C: Chain>(
    config: Arc<ZalletConfig>,
    wallet: DbHandle,
    keystore: KeyStore,
    chain: C,
    account: JsonValue,
    fund_source: JsonValue,
    recipients: Vec<AmountParameter>,
    minconf: Option<u32>,
    privacy_policy: String,
) -> Response {
    let request = build_request(&recipients)?;

    let account_id = parse_account_parameter(wallet.as_ref(), &keystore, &account).await?;

    // Fetch the account up front: it both validates that the account exists and provides the
    // key derivation needed to sign the transaction.
    let account = wallet
        .as_ref()
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| {
            LegacyCode::InvalidParameter
                .with_message(format!("No account with UUID {}", account_id.expose_uuid()))
        })?;

    let fund_source = FundSource::parse(&fund_source, wallet.params())?;

    // Unlike `z_proposetransaction`, the caller must explicitly acknowledge the privacy
    // implications of the one-shot send by supplying the privacy policy to enforce.
    let privacy_policy = parse_privacy_policy(Some(&privacy_policy))?;

    let confirmations_policy = match minconf {
        Some(minconf) => NonZeroU32::new(minconf).map_or(
            ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
            |c| ConfirmationsPolicy::new_symmetrical(c, false),
        ),
        None => {
            config.builder.confirmations_policy().map_err(|_| {
                LegacyCode::Wallet.with_message(
                    "Configuration error: minimum confirmations for spending trusted TXOs cannot exceed that for untrusted TXOs.")
            })?
        }
    };

    let params = *wallet.params();

    // Propose the transfer with inputs restricted to the requested fund source. The filter
    // borrows the connection immutably; scope it so that borrow is released before we take a
    // mutable borrow to build and sign the transaction.
    let proposal = {
        let change_strategy = MultiOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedProtocol::Orchard,
            DustOutputPolicy::default(),
            config.note_management.split_policy(),
        );
        let input_selector = GreedyInputSelector::new();
        let mut source = FundSourceFilter::new(wallet.as_ref(), fund_source);

        propose_transfer::<_, _, _, _, Infallible>(
            &mut source,
            &params,
            account_id,
            &input_selector,
            &change_strategy,
            request,
            confirmations_policy,
        )
        // TODO: Map errors to `zcashd` shape.
        .map_err(|e| {
            LegacyCode::Wallet.with_message(format!("Failed to propose transaction: {e}"))
        })?
    };

    enforce_privacy_policy(&proposal, privacy_policy)?;

    check_orchard_actions_limit(&config, &proposal)?;

    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey
            .with_static("Cannot spend from an account that has no spending key.")
    })?;

    // Fetch the spending key last, to avoid a keystore decryption if unnecessary.
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

    #[cfg(feature = "zcashd-import")]
    let standalone_keys =
        collect_standalone_transparent_keys(wallet.as_ref(), &keystore, account_id, &proposal)
            .await?;

    // Unlike `z_sendmany`, this performs the entire operation in one shot rather than using
    // the background processing system.
    run(
        config,
        wallet,
        chain,
        proposal,
        #[cfg(feature = "zcashd-import")]
        SpendingKeys::new(usk, standalone_keys),
        #[cfg(not(feature = "zcashd-import"))]
        SpendingKeys::from_unified_spending_key(usk),
    )
    .await
}

/// End-to-end coverage of `z_sendfromaccount` driven exactly as the RPC dispatcher drives it:
/// against a real funded wallet, with a real keystore deriving the spending key, producing and
/// storing a fully-signed transaction (broadcasting disabled).
#[cfg(test)]
mod rpc_e2e_tests {
    use std::io::Write as _;
    use std::sync::Arc;

    use age::secrecy::ExposeSecret;
    use bip0039::{English, Mnemonic};
    use incrementalmerkletree::frontier::Frontier;
    use secrecy::SecretVec;
    use serde_json::json;
    use zcash_client_backend::data_api::{
        Account as _,
        chain::ChainState,
        testing::{
            AddressType, InitialChainState, TestBuilder, orchard::OrchardPoolTester,
            pool::ShieldedPoolTester,
        },
    };
    use zcash_client_sqlite::testing::{BlockCache, db::TestDbFactory};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{
        consensus::{NetworkUpgrade, Parameters, ZIP212_GRACE_PERIOD},
        value::Zatoshis,
    };

    use crate::{
        components::{
            chain::{ChainBlock, testing::TestChain},
            database::Database,
            json_rpc::payments::AmountParameter,
            keystore::KeyStore,
        },
        config::ZalletConfig,
        network::Network,
    };

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::field_reassign_with_default)]
    async fn send_from_account_builds_and_stores_a_transaction() {
        // A mnemonic-derived seed, so zallet's mnemonic-based keystore can reproduce the
        // account's spending key.
        let mnemonic = Mnemonic::<English>::from_entropy(vec![7u8; 32]).unwrap();
        let seed = SecretVec::new(mnemonic.to_seed("").to_vec());

        // A funded Orchard wallet derived from that seed.
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_seed(seed)
            .with_initial_chain_state(|_, network| {
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
        let fvk = OrchardPoolTester::test_account_fvk(&st);
        st.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(1_000_000),
        );
        st.scan_cached_blocks(account.birthday().height(), 1);

        let recipient = OrchardPoolTester::fvk_default_address(&fvk)
            .to_zcash_address(st.network())
            .encode();
        let db_path = st.wallet().path().to_path_buf();
        let account_uuid = account.id().expose_uuid().to_string();
        let network = Network::RegTest(TestBuilder::<(), ()>::DEFAULT_NETWORK);

        // zallet's own database, opened over the same funded SQLite file.
        let db = Database::open_funded_for_test(&db_path, network)
            .await
            .unwrap();

        // A keystore holding the account's mnemonic, unlocked by a native age identity.
        let identity = age::x25519::Identity::generate();
        let mut identity_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(identity_file, "{}", identity.to_string().expose_secret()).unwrap();
        let mut config = ZalletConfig::default();
        // `encryption_identity()` resolves relative to the datadir; our path is absolute, but
        // the datadir getter still must be set to avoid a panic.
        config.datadir = Some(std::env::temp_dir());
        config.keystore.encryption_identity = Some(identity_file.path().to_path_buf());
        let keystore = KeyStore::new(&config, db.clone()).unwrap();
        keystore
            .initialize_recipients(vec![identity.to_public().to_string()])
            .await
            .unwrap();
        keystore.encrypt_and_store_mnemonic(mnemonic).await.unwrap();

        // Drive the RPC method exactly as the dispatcher does.
        let chain = TestChain::new(ChainBlock {
            height: account.birthday().height(),
            hash: BlockHash([0; 32]),
        });
        let recipients: Vec<AmountParameter> = vec![
            serde_json::from_value(json!({ "address": recipient, "amount": "0.002" })).unwrap(),
        ];
        let db_handle = db.handle().await.unwrap();

        let result = super::call(
            Arc::new(config),
            db_handle,
            keystore,
            chain,
            json!(account_uuid),
            json!("orchard"),
            recipients,
            Some(1),
            "AllowRevealedAmounts".to_string(),
        )
        .await;

        let send_result =
            result.expect("z_sendfromaccount should build, sign, and store a transaction");
        let json = serde_json::to_value(&send_result).unwrap();
        assert!(
            json.get("txid")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "a resulting transaction id should be returned: {json:?}",
        );
    }
}
