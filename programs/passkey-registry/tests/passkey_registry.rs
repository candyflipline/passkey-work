#![cfg(feature = "test-sbf")]

use anchor_lang::{
    AccountDeserialize, AccountSerialize, AnchorDeserialize, AnchorSerialize, InstructionData,
};
use light_program_test::{
    program_test::LightProgramTest, AddressWithTree, Indexer, ProgramTestConfig, Rpc, RpcError,
};
use light_sdk::{
    address::v2::derive_address,
    instruction::{account_meta::CompressedAccountMeta, PackedAccounts, SystemAccountMetaConfig},
};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
};
use passkey_registry::{
    build_registration_challenge, compressed_p256_pubkey, derive_wallet_authority_address,
    wallet_authority_hash, PasskeyAuthority, PoolAllocator, PoolDirectory, AUTHORITY_KIND_PASSKEY,
    AUTHORITY_KIND_WALLET, PASSKEY_AUTHORITY_SEED, POOL_ALLOCATOR_SEED,
    POOL_ALLOCATOR_STATUS_ACTIVE, POOL_ALLOCATOR_VERSION, POOL_DIRECTORY_SEED,
    POOL_DIRECTORY_STATUS_ACTIVE, POOL_DIRECTORY_VERSION,
};
use solana_sdk::{
    account::Account,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
    signature::{Keypair, Signature, Signer},
    system_instruction, sysvar,
};
use std::{env, fs, path::Path, sync::Mutex};

static LIGHT_PROGRAM_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn lite_svm_can_derive_the_prf_authority_signer() {
    let mut svm = litesvm::LiteSVM::new();
    let authority = prf_derived_authority();

    svm.airdrop(&authority.pubkey(), 1_000_000_000).unwrap();

    let account = svm.get_account(&authority.pubkey()).unwrap();
    assert_eq!(account.lamports, 1_000_000_000);
}

#[test]
fn pool_allocator_uses_all_256_vault_indexes() {
    let squads_settings = Keypair::new().pubkey();
    let mut allocator = PoolAllocator {
        version: POOL_ALLOCATOR_VERSION,
        status: POOL_ALLOCATOR_STATUS_ACTIVE,
        squads_settings,
        next_index: 0,
        ..Default::default()
    };

    for expected_index in 0..=u8::MAX {
        assert_eq!(allocator.next_vault_index().unwrap(), expected_index);
        allocator.allocate_next(expected_index).unwrap();
    }

    assert_eq!(allocator.next_index, 256);
    assert!(allocator.next_vault_index().is_err());
}

#[test]
fn pool_allocator_reports_capacity_for_rollover() {
    let squads_settings = Keypair::new().pubkey();
    let mut allocator = PoolAllocator {
        version: POOL_ALLOCATOR_VERSION,
        status: POOL_ALLOCATOR_STATUS_ACTIVE,
        squads_settings,
        next_index: 255,
        ..Default::default()
    };

    assert!(!allocator.is_exhausted());
    assert_eq!(allocator.next_vault_index().unwrap(), 255);
    allocator.allocate_next(255).unwrap();
    assert_eq!(allocator.next_index, 256);
    assert!(allocator.is_exhausted());
}

#[tokio::test(flavor = "current_thread")]
async fn creates_passkey_authority_compressed_pda() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let authority = prf_derived_authority();
    let (verifier, _) = passkey_registry::derive_verifier_pda();
    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier, 1)
        .await
        .unwrap();
    let (pool_allocator, _) = solana_sdk::pubkey::Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, squads_settings.as_ref()],
        &passkey_registry::ID,
    );

    rpc.airdrop_lamports(&authority.pubkey(), 1_000_000_000)
        .await
        .unwrap();
    initialize_pool_allocator(&mut rpc, &payer, pool_allocator, squads_settings)
        .await
        .unwrap();

    let credential_id_hash = hash32(b"loyal-test-credential-id");
    let address_tree_info = rpc.get_address_tree_v2();
    let (address, _) = derive_address(
        &[PASSKEY_AUTHORITY_SEED, credential_id_hash.as_ref()],
        &address_tree_info.tree,
        &passkey_registry::ID,
    );

    let (passkey_pubkey_compressed, secp256r1_instruction) = create_passkey_signature_instruction(
        &credential_id_hash,
        &authority.pubkey(),
        &address_tree_info.tree,
        &squads_settings,
        0,
    );

    create_passkey_authority(
        &mut rpc,
        &payer,
        &authority,
        pool_allocator,
        &address,
        secp256r1_instruction,
        credential_id_hash,
        passkey_pubkey_compressed,
    )
    .await
    .unwrap();

    let compressed_account = rpc
        .get_compressed_account(address, None)
        .await
        .unwrap()
        .value
        .unwrap();
    let data = &compressed_account.data.as_ref().unwrap().data;
    let authority_record = PasskeyAuthority::deserialize(&mut &data[..]).unwrap();

    assert_eq!(
        authority_record.version,
        passkey_registry::PASSKEY_AUTHORITY_VERSION
    );
    assert_eq!(
        authority_record.status,
        passkey_registry::PASSKEY_AUTHORITY_STATUS_ACTIVE
    );
    assert_eq!(authority_record.authority_kind, AUTHORITY_KIND_PASSKEY);
    assert_eq!(authority_record.credential_id_hash, credential_id_hash);
    assert_eq!(
        authority_record.passkey_pubkey_prefix,
        passkey_pubkey_compressed[0]
    );
    assert_eq!(
        authority_record.passkey_pubkey_x,
        passkey_pubkey_compressed[1..]
    );
    assert_eq!(authority_record.ed25519_authority, authority.pubkey());
    assert_eq!(authority_record.squads_settings, squads_settings);
    assert_eq!(authority_record.vault_index, 0);
    assert_eq!(authority_record.nonce, 0);

    let allocator_account = rpc.get_account(pool_allocator).await.unwrap().unwrap();
    let allocator = PoolAllocator::try_deserialize(&mut allocator_account.data.as_slice()).unwrap();
    assert_eq!(allocator.squads_settings, squads_settings);
    assert_eq!(allocator.next_index, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn creates_wallet_authority_compressed_pda() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let wallet = Keypair::new();
    let (verifier, _) = passkey_registry::derive_verifier_pda();
    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier, 1)
        .await
        .unwrap();
    let (pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, squads_settings.as_ref()],
        &passkey_registry::ID,
    );

    rpc.airdrop_lamports(&wallet.pubkey(), 1_000_000_000)
        .await
        .unwrap();
    initialize_pool_allocator(&mut rpc, &payer, pool_allocator, squads_settings)
        .await
        .unwrap();

    let address_tree_info = rpc.get_address_tree_v2();
    let wallet_hash = wallet_authority_hash(&wallet.pubkey());
    let (address, _) = derive_wallet_authority_address(&wallet_hash, &address_tree_info.tree);

    create_wallet_authority(&mut rpc, &payer, &wallet, pool_allocator, &address)
        .await
        .unwrap();

    let authority_record = fetch_passkey_authority(&rpc, address).await;
    assert_eq!(
        authority_record.version,
        passkey_registry::PASSKEY_AUTHORITY_VERSION
    );
    assert_eq!(
        authority_record.status,
        passkey_registry::PASSKEY_AUTHORITY_STATUS_ACTIVE
    );
    assert_eq!(authority_record.authority_kind, AUTHORITY_KIND_WALLET);
    assert_eq!(authority_record.credential_id_hash, wallet_hash);
    assert_eq!(authority_record.passkey_pubkey_prefix, 0);
    assert_eq!(authority_record.passkey_pubkey_x, [0; 32]);
    assert_eq!(authority_record.ed25519_authority, wallet.pubkey());
    assert_eq!(authority_record.squads_settings, squads_settings);
    assert_eq!(authority_record.vault_index, 0);
    assert_eq!(authority_record.nonce, 0);

    let allocator_account = rpc.get_account(pool_allocator).await.unwrap().unwrap();
    let allocator = PoolAllocator::try_deserialize(&mut allocator_account.data.as_slice()).unwrap();
    assert_eq!(allocator.squads_settings, squads_settings);
    assert_eq!(allocator.next_index, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn shared_pool_allocator_prevents_wallet_and_passkey_vault_collisions() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let wallet = Keypair::new();
    let passkey_authority = prf_derived_authority();
    let (verifier, _) = passkey_registry::derive_verifier_pda();
    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier, 1)
        .await
        .unwrap();
    let (pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, squads_settings.as_ref()],
        &passkey_registry::ID,
    );

    rpc.airdrop_lamports(&wallet.pubkey(), 1_000_000_000)
        .await
        .unwrap();
    rpc.airdrop_lamports(&passkey_authority.pubkey(), 1_000_000_000)
        .await
        .unwrap();
    initialize_pool_allocator(&mut rpc, &payer, pool_allocator, squads_settings)
        .await
        .unwrap();

    let address_tree_info = rpc.get_address_tree_v2();
    let credential_id_hash = hash32(b"loyal-test-shared-allocator-passkey");
    let (passkey_address, _) = derive_address(
        &[PASSKEY_AUTHORITY_SEED, credential_id_hash.as_ref()],
        &address_tree_info.tree,
        &passkey_registry::ID,
    );

    let (stale_passkey_pubkey, stale_vault_zero_assertion) = create_passkey_signature_instruction(
        &credential_id_hash,
        &passkey_authority.pubkey(),
        &address_tree_info.tree,
        &squads_settings,
        0,
    );

    let wallet_hash = wallet_authority_hash(&wallet.pubkey());
    let (wallet_address, _) =
        derive_wallet_authority_address(&wallet_hash, &address_tree_info.tree);
    create_wallet_authority(&mut rpc, &payer, &wallet, pool_allocator, &wallet_address)
        .await
        .unwrap();

    let wallet_record = fetch_passkey_authority(&rpc, wallet_address).await;
    assert_eq!(wallet_record.authority_kind, AUTHORITY_KIND_WALLET);
    assert_eq!(wallet_record.vault_index, 0);

    assert!(create_passkey_authority(
        &mut rpc,
        &payer,
        &passkey_authority,
        pool_allocator,
        &passkey_address,
        stale_vault_zero_assertion,
        credential_id_hash,
        stale_passkey_pubkey,
    )
    .await
    .is_err());

    let allocator_account = rpc.get_account(pool_allocator).await.unwrap().unwrap();
    let allocator = PoolAllocator::try_deserialize(&mut allocator_account.data.as_slice()).unwrap();
    assert_eq!(allocator.next_index, 1);

    let (fresh_passkey_pubkey, fresh_vault_one_assertion) = create_passkey_signature_instruction(
        &credential_id_hash,
        &passkey_authority.pubkey(),
        &address_tree_info.tree,
        &squads_settings,
        1,
    );

    create_passkey_authority(
        &mut rpc,
        &payer,
        &passkey_authority,
        pool_allocator,
        &passkey_address,
        fresh_vault_one_assertion,
        credential_id_hash,
        fresh_passkey_pubkey,
    )
    .await
    .unwrap();

    let passkey_record = fetch_passkey_authority(&rpc, passkey_address).await;
    assert_eq!(passkey_record.authority_kind, AUTHORITY_KIND_PASSKEY);
    assert_eq!(passkey_record.vault_index, 1);
    assert_eq!(passkey_record.squads_settings, squads_settings);

    let allocator_account = rpc.get_account(pool_allocator).await.unwrap().unwrap();
    let allocator = PoolAllocator::try_deserialize(&mut allocator_account.data.as_slice()).unwrap();
    assert_eq!(allocator.next_index, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn pool_allocator_can_hold_and_withdraw_rollover_float() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let (verifier, _) = passkey_registry::derive_verifier_pda();
    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier, 1)
        .await
        .unwrap();
    let (pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, squads_settings.as_ref()],
        &passkey_registry::ID,
    );
    initialize_pool_allocator(&mut rpc, &payer, pool_allocator, squads_settings)
        .await
        .unwrap();

    let allocator_start_balance = get_balance_or_zero(&rpc, pool_allocator).await;
    fund_pool_allocator(&mut rpc, &payer, pool_allocator, 7_000_000)
        .await
        .unwrap();
    assert_eq!(
        get_balance_or_zero(&rpc, pool_allocator).await,
        allocator_start_balance + 7_000_000
    );

    let unauthorized = Keypair::new();
    rpc.airdrop_lamports(&unauthorized.pubkey(), 1_000_000_000)
        .await
        .unwrap();
    assert!(withdraw_pool_allocator_surplus(
        &mut rpc,
        &unauthorized,
        pool_allocator,
        unauthorized.pubkey(),
        1_000_000,
        allocator_start_balance
    )
    .await
    .is_err());

    let recipient = Keypair::new();
    rpc.airdrop_lamports(&recipient.pubkey(), 1_000_000)
        .await
        .unwrap();
    let recipient_start_balance = get_balance_or_zero(&rpc, recipient.pubkey()).await;
    withdraw_pool_allocator_surplus(
        &mut rpc,
        &payer,
        pool_allocator,
        recipient.pubkey(),
        2_000_000,
        allocator_start_balance + 5_000_000,
    )
    .await
    .unwrap();

    assert_eq!(
        get_balance_or_zero(&rpc, recipient.pubkey()).await,
        recipient_start_balance + 2_000_000
    );
    assert_eq!(
        get_balance_or_zero(&rpc, pool_allocator).await,
        allocator_start_balance + 5_000_000
    );
}

#[tokio::test(flavor = "current_thread")]
async fn pool_directory_tracks_the_active_squads_pool() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let (verifier, _) = passkey_registry::derive_verifier_pda();
    let first_pool_index = 1;
    let first_squads_settings =
        create_squads_smart_account(&mut rpc, &payer, verifier, first_pool_index)
            .await
            .unwrap();
    let (first_pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, first_squads_settings.as_ref()],
        &passkey_registry::ID,
    );
    initialize_pool_allocator(
        &mut rpc,
        &payer,
        first_pool_allocator,
        first_squads_settings,
    )
    .await
    .unwrap();

    let address_tree_info = rpc.get_address_tree_v2();
    let (directory_address, _) = derive_address(
        &[POOL_DIRECTORY_SEED],
        &address_tree_info.tree,
        &passkey_registry::ID,
    );

    initialize_pool_directory(
        &mut rpc,
        &payer,
        first_pool_allocator,
        first_squads_settings,
        &directory_address,
        first_pool_index,
    )
    .await
    .unwrap();

    let directory = fetch_pool_directory(&rpc, directory_address).await;
    assert_eq!(directory.version, POOL_DIRECTORY_VERSION);
    assert_eq!(directory.status, POOL_DIRECTORY_STATUS_ACTIVE);
    assert_eq!(directory.active_pool_index, first_pool_index);

    set_pool_allocator_next_index(&mut rpc, first_pool_allocator, 250).await;
    for vault_index in 250..=u8::MAX {
        let authority = Keypair::new();
        rpc.airdrop_lamports(&authority.pubkey(), 1_000_000)
            .await
            .unwrap();
        let (authority_address, expected_kind) = if vault_index % 2 == 0 {
            let credential_id_hash =
                hashv(&[b"loyal-test-near-full-pool-credential", &[vault_index]]).to_bytes();
            let (authority_address, _) = derive_address(
                &[PASSKEY_AUTHORITY_SEED, credential_id_hash.as_ref()],
                &address_tree_info.tree,
                &passkey_registry::ID,
            );
            let (passkey_pubkey_compressed, secp256r1_instruction) =
                create_passkey_signature_instruction(
                    &credential_id_hash,
                    &authority.pubkey(),
                    &address_tree_info.tree,
                    &first_squads_settings,
                    vault_index,
                );

            create_passkey_authority(
                &mut rpc,
                &payer,
                &authority,
                first_pool_allocator,
                &authority_address,
                secp256r1_instruction,
                credential_id_hash,
                passkey_pubkey_compressed,
            )
            .await
            .unwrap();

            (authority_address, AUTHORITY_KIND_PASSKEY)
        } else {
            let wallet_hash = wallet_authority_hash(&authority.pubkey());
            let (authority_address, _) =
                derive_wallet_authority_address(&wallet_hash, &address_tree_info.tree);

            create_wallet_authority(
                &mut rpc,
                &payer,
                &authority,
                first_pool_allocator,
                &authority_address,
            )
            .await
            .unwrap();

            (authority_address, AUTHORITY_KIND_WALLET)
        };

        let authority_record = fetch_passkey_authority(&rpc, authority_address).await;
        assert_eq!(authority_record.authority_kind, expected_kind);
        assert_eq!(authority_record.squads_settings, first_squads_settings);
        assert_eq!(authority_record.vault_index, vault_index);
    }

    let first_allocator_account = rpc
        .get_account(first_pool_allocator)
        .await
        .unwrap()
        .unwrap();
    let first_allocator =
        PoolAllocator::try_deserialize(&mut first_allocator_account.data.as_slice()).unwrap();
    assert_eq!(first_allocator.next_index, 256);
    assert!(first_allocator.is_exhausted());

    rpc.airdrop_lamports(&first_pool_allocator, 20_000_000)
        .await
        .unwrap();
    let first_allocator_start_balance = get_balance_or_zero(&rpc, first_pool_allocator).await;
    let next_allocator_lamports = 5_000_000;

    let next_pool_index = first_pool_index + 1;
    let next_squads_settings = passkey_registry::derive_squads_settings(next_pool_index).0;
    let (next_pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, next_squads_settings.as_ref()],
        &passkey_registry::ID,
    );
    let program_config = derive_squads_program_config();

    provision_next_pool(
        &mut rpc,
        &payer,
        first_pool_allocator,
        program_config,
        squads_treasury(),
        next_squads_settings,
        next_pool_allocator,
        &directory_address,
        first_pool_index,
        next_allocator_lamports,
    )
    .await
    .unwrap();

    let directory = fetch_pool_directory(&rpc, directory_address).await;
    assert_eq!(directory.active_pool_index, next_pool_index);

    let next_squads_settings_account = rpc
        .get_account(next_squads_settings)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        next_squads_settings_account.owner,
        passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID
    );

    let allocator_account = rpc.get_account(next_pool_allocator).await.unwrap().unwrap();
    let allocator = PoolAllocator::try_deserialize(&mut allocator_account.data.as_slice()).unwrap();
    assert_eq!(allocator.squads_settings, next_squads_settings);
    assert_eq!(allocator.next_index, 0);
    assert!(allocator_account.lamports >= next_allocator_lamports);

    let squads_settings_rent =
        Rent::default().minimum_balance(passkey_registry::SQUADS_ONE_SIGNER_SETTINGS_SPACE);
    assert_eq!(
        get_balance_or_zero(&rpc, first_pool_allocator).await,
        first_allocator_start_balance - squads_settings_rent - next_allocator_lamports
    );
    assert_eq!(
        get_balance_or_zero(&rpc, next_squads_settings).await,
        squads_settings_rent
    );

    let authority = prf_derived_authority();
    rpc.airdrop_lamports(&authority.pubkey(), 1_000_000_000)
        .await
        .unwrap();
    let wallet_hash = wallet_authority_hash(&authority.pubkey());
    let (authority_address, _) =
        derive_wallet_authority_address(&wallet_hash, &address_tree_info.tree);

    create_wallet_authority(
        &mut rpc,
        &payer,
        &authority,
        next_pool_allocator,
        &authority_address,
    )
    .await
    .unwrap();

    let authority_record = fetch_passkey_authority(&rpc, authority_address).await;
    assert_eq!(authority_record.authority_kind, AUTHORITY_KIND_WALLET);
    assert_eq!(authority_record.squads_settings, next_squads_settings);
    assert_eq!(authority_record.vault_index, 0);

    let allocator_account = rpc.get_account(next_pool_allocator).await.unwrap().unwrap();
    let allocator = PoolAllocator::try_deserialize(&mut allocator_account.data.as_slice()).unwrap();
    assert_eq!(allocator.next_index, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn pool_directory_does_not_advance_while_current_pool_has_capacity() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let (verifier, _) = passkey_registry::derive_verifier_pda();
    let first_pool_index = 1;
    let first_squads_settings =
        create_squads_smart_account(&mut rpc, &payer, verifier, first_pool_index)
            .await
            .unwrap();
    let (first_pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, first_squads_settings.as_ref()],
        &passkey_registry::ID,
    );
    initialize_pool_allocator(
        &mut rpc,
        &payer,
        first_pool_allocator,
        first_squads_settings,
    )
    .await
    .unwrap();

    let address_tree_info = rpc.get_address_tree_v2();
    let (directory_address, _) = derive_address(
        &[POOL_DIRECTORY_SEED],
        &address_tree_info.tree,
        &passkey_registry::ID,
    );
    initialize_pool_directory(
        &mut rpc,
        &payer,
        first_pool_allocator,
        first_squads_settings,
        &directory_address,
        first_pool_index,
    )
    .await
    .unwrap();

    let next_squads_settings = passkey_registry::derive_squads_settings(2).0;
    let (next_pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, next_squads_settings.as_ref()],
        &passkey_registry::ID,
    );
    let program_config = derive_squads_program_config();

    assert!(provision_next_pool(
        &mut rpc,
        &payer,
        first_pool_allocator,
        program_config,
        squads_treasury(),
        next_squads_settings,
        next_pool_allocator,
        &directory_address,
        first_pool_index,
        5_000_000,
    )
    .await
    .is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_allocator_for_unvalidated_squads_settings() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config =
        ProgramTestConfig::new_v2(true, Some(vec![("passkey_registry", passkey_registry::ID)]));
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let fake_settings = Keypair::new().pubkey();
    let (pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, fake_settings.as_ref()],
        &passkey_registry::ID,
    );

    rpc.context
        .set_account(
            fake_settings,
            Account {
                lamports: 1_000_000,
                data: vec![],
                owner: solana_sdk::system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    assert!(
        initialize_pool_allocator(&mut rpc, &payer, pool_allocator, fake_settings)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn passkey_verifier_executes_squads_vault_transfer() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let authority = prf_derived_authority();
    let recipient = Keypair::new();
    let (verifier, _) = passkey_registry::derive_verifier_pda();

    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier, 1)
        .await
        .unwrap();
    let (pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, squads_settings.as_ref()],
        &passkey_registry::ID,
    );

    initialize_pool_allocator(&mut rpc, &payer, pool_allocator, squads_settings)
        .await
        .unwrap();
    rpc.airdrop_lamports(&authority.pubkey(), 1_000_000_000)
        .await
        .unwrap();

    let credential_id_hash = hash32(b"loyal-test-squads-credential-id");
    let address_tree_info = rpc.get_address_tree_v2();
    let (address, _) = derive_address(
        &[PASSKEY_AUTHORITY_SEED, credential_id_hash.as_ref()],
        &address_tree_info.tree,
        &passkey_registry::ID,
    );

    let test_passkey = TestPasskey::new();
    let secp256r1_registration_instruction = test_passkey.registration_instruction(
        &credential_id_hash,
        &authority.pubkey(),
        &address_tree_info.tree,
        &squads_settings,
        0,
    );

    create_passkey_authority(
        &mut rpc,
        &payer,
        &authority,
        pool_allocator,
        &address,
        secp256r1_registration_instruction,
        credential_id_hash,
        test_passkey.compressed_pubkey,
    )
    .await
    .unwrap();

    let (vault_0, _) = passkey_registry::derive_squads_vault(&squads_settings, 0);
    let transfer_to_vault_lamports = 20_000_000;
    let transfer_back_lamports = 7_000_000;
    rpc.create_and_send_transaction(
        &[system_instruction::transfer(
            &payer.pubkey(),
            &vault_0,
            transfer_to_vault_lamports,
        )],
        &payer.pubkey(),
        &[&payer],
    )
    .await
    .unwrap();

    let recipient_start_balance = get_balance_or_zero(&rpc, recipient.pubkey()).await;
    let vault_start_balance = get_balance_or_zero(&rpc, vault_0).await;
    assert_eq!(vault_start_balance, transfer_to_vault_lamports);

    execute_passkey_vault_transfer(
        &mut rpc,
        &payer,
        &address,
        &test_passkey,
        recipient.pubkey(),
        transfer_back_lamports,
    )
    .await
    .unwrap();

    let recipient_end_balance = get_balance_or_zero(&rpc, recipient.pubkey()).await;
    let vault_end_balance = get_balance_or_zero(&rpc, vault_0).await;
    assert_eq!(
        recipient_end_balance - recipient_start_balance,
        transfer_back_lamports
    );
    assert_eq!(
        vault_start_balance - vault_end_balance,
        transfer_back_lamports
    );

    let compressed_account = rpc
        .get_compressed_account(address, None)
        .await
        .unwrap()
        .value
        .unwrap();
    let data = &compressed_account.data.as_ref().unwrap().data;
    let authority_record = PasskeyAuthority::deserialize(&mut &data[..]).unwrap();
    assert_eq!(authority_record.vault_index, 0);
    assert_eq!(authority_record.squads_settings, squads_settings);
    assert_eq!(authority_record.nonce, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn wallet_verifier_executes_squads_vault_transfer() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let wallet = Keypair::new();
    let recipient = Keypair::new();
    let (verifier, _) = passkey_registry::derive_verifier_pda();

    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier, 1)
        .await
        .unwrap();
    let (pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, squads_settings.as_ref()],
        &passkey_registry::ID,
    );

    initialize_pool_allocator(&mut rpc, &payer, pool_allocator, squads_settings)
        .await
        .unwrap();
    rpc.airdrop_lamports(&wallet.pubkey(), 1_000_000_000)
        .await
        .unwrap();

    let address_tree_info = rpc.get_address_tree_v2();
    let wallet_hash = wallet_authority_hash(&wallet.pubkey());
    let (address, _) = derive_wallet_authority_address(&wallet_hash, &address_tree_info.tree);
    create_wallet_authority(&mut rpc, &payer, &wallet, pool_allocator, &address)
        .await
        .unwrap();

    let (vault_0, _) = passkey_registry::derive_squads_vault(&squads_settings, 0);
    let transfer_to_vault_lamports = 20_000_000;
    let transfer_back_lamports = 7_000_000;
    rpc.create_and_send_transaction(
        &[system_instruction::transfer(
            &payer.pubkey(),
            &vault_0,
            transfer_to_vault_lamports,
        )],
        &payer.pubkey(),
        &[&payer],
    )
    .await
    .unwrap();

    let recipient_start_balance = get_balance_or_zero(&rpc, recipient.pubkey()).await;
    let vault_start_balance = get_balance_or_zero(&rpc, vault_0).await;
    execute_wallet_vault_transfer(
        &mut rpc,
        &payer,
        &wallet,
        &address,
        recipient.pubkey(),
        transfer_back_lamports,
    )
    .await
    .unwrap();

    let recipient_end_balance = get_balance_or_zero(&rpc, recipient.pubkey()).await;
    let vault_end_balance = get_balance_or_zero(&rpc, vault_0).await;
    assert_eq!(
        recipient_end_balance - recipient_start_balance,
        transfer_back_lamports
    );
    assert_eq!(
        vault_start_balance - vault_end_balance,
        transfer_back_lamports
    );

    let authority_record = fetch_passkey_authority(&rpc, address).await;
    assert_eq!(authority_record.authority_kind, AUTHORITY_KIND_WALLET);
    assert_eq!(authority_record.vault_index, 0);
    assert_eq!(authority_record.squads_settings, squads_settings);
    assert_eq!(authority_record.nonce, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_wallet_execution_from_wrong_signer() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let wallet = Keypair::new();
    let wrong_wallet = Keypair::new();
    let recipient = Keypair::new();
    let (verifier, _) = passkey_registry::derive_verifier_pda();

    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier, 1)
        .await
        .unwrap();
    let (pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, squads_settings.as_ref()],
        &passkey_registry::ID,
    );
    initialize_pool_allocator(&mut rpc, &payer, pool_allocator, squads_settings)
        .await
        .unwrap();
    rpc.airdrop_lamports(&wallet.pubkey(), 1_000_000_000)
        .await
        .unwrap();
    rpc.airdrop_lamports(&wrong_wallet.pubkey(), 1_000_000_000)
        .await
        .unwrap();

    let address_tree_info = rpc.get_address_tree_v2();
    let wallet_hash = wallet_authority_hash(&wallet.pubkey());
    let (address, _) = derive_wallet_authority_address(&wallet_hash, &address_tree_info.tree);
    create_wallet_authority(&mut rpc, &payer, &wallet, pool_allocator, &address)
        .await
        .unwrap();

    assert!(execute_wallet_vault_transfer(
        &mut rpc,
        &payer,
        &wrong_wallet,
        &address,
        recipient.pubkey(),
        1_000_000,
    )
    .await
    .is_err());

    let authority_record = fetch_passkey_authority(&rpc, address).await;
    assert_eq!(authority_record.nonce, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_secp256r1_instruction_after_registry_instruction() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config = ProgramTestConfig::new_v2(
        true,
        Some(vec![
            ("passkey_registry", passkey_registry::ID),
            (
                SQUADS_SMART_ACCOUNT_PROGRAM_NAME,
                passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
            ),
        ]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let authority = prf_derived_authority();
    let (verifier, _) = passkey_registry::derive_verifier_pda();
    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier, 1)
        .await
        .unwrap();
    let (pool_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, squads_settings.as_ref()],
        &passkey_registry::ID,
    );

    initialize_pool_allocator(&mut rpc, &payer, pool_allocator, squads_settings)
        .await
        .unwrap();
    rpc.airdrop_lamports(&authority.pubkey(), 1_000_000_000)
        .await
        .unwrap();

    let credential_id_hash = hash32(b"loyal-test-late-secp-credential-id");
    let address_tree_info = rpc.get_address_tree_v2();
    let (address, _) = derive_address(
        &[PASSKEY_AUTHORITY_SEED, credential_id_hash.as_ref()],
        &address_tree_info.tree,
        &passkey_registry::ID,
    );
    let (passkey_pubkey_compressed, secp256r1_instruction) = create_passkey_signature_instruction(
        &credential_id_hash,
        &authority.pubkey(),
        &address_tree_info.tree,
        &squads_settings,
        0,
    );

    assert!(create_passkey_authority_with_instruction_order(
        &mut rpc,
        &payer,
        &authority,
        pool_allocator,
        &address,
        secp256r1_instruction,
        credential_id_hash,
        passkey_pubkey_compressed,
        1,
        false,
    )
    .await
    .is_err());
}

async fn initialize_pool_allocator(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    pool_allocator: solana_sdk::pubkey::Pubkey,
    squads_settings: solana_sdk::pubkey::Pubkey,
) -> Result<Signature, RpcError> {
    let (compression_config, pda_rent_sponsor) =
        ensure_pool_allocator_light_config(rpc, payer).await?;
    let mut remaining_accounts = PackedAccounts::default();
    remaining_accounts
        .add_system_accounts_v2(SystemAccountMetaConfig::new(passkey_registry::ID))?;

    let address_tree_info = rpc.get_address_tree_v2();
    let light_pda_address = light_compressed_account::address::derive_address(
        &pool_allocator.to_bytes(),
        &address_tree_info.tree.to_bytes(),
        &passkey_registry::ID.to_bytes(),
    );
    let proof_result = rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address: light_pda_address,
                tree: address_tree_info.tree,
            }],
            None,
        )
        .await?
        .value;
    let packed_accounts = proof_result.pack_tree_infos(&mut remaining_accounts);
    let output_state_tree_index = rpc
        .get_random_state_tree_info()?
        .pack_output_tree_index(&mut remaining_accounts)?;
    let (remaining_account_metas, _, _) = remaining_accounts.to_account_metas();

    let create_accounts_proof = light_account::CreateAccountsProof {
        proof: proof_result.proof,
        address_tree_info: packed_accounts.address_trees[0],
        output_state_tree_index,
        state_tree_index: None,
        system_accounts_offset: 0,
    };
    let instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: [
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(compression_config, false),
                AccountMeta::new(pda_rent_sponsor, false),
                AccountMeta::new_readonly(squads_settings, false),
                AccountMeta::new(pool_allocator, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            remaining_account_metas,
        ]
        .concat(),
        data: passkey_registry::instruction::InitializePoolAllocator {
            params: passkey_registry::InitializePoolAllocatorParams {
                create_accounts_proof,
                squads_settings,
                withdraw_authority: payer.pubkey(),
            },
        }
        .data(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await
}

async fn fund_pool_allocator(
    rpc: &mut LightProgramTest,
    funder: &Keypair,
    pool_allocator: Pubkey,
    lamports: u64,
) -> Result<Signature, RpcError> {
    let instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: vec![
            AccountMeta::new(funder.pubkey(), true),
            AccountMeta::new(pool_allocator, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data: passkey_registry::instruction::FundPoolAllocator { lamports }.data(),
    };

    rpc.create_and_send_transaction(&[instruction], &funder.pubkey(), &[funder])
        .await
}

async fn withdraw_pool_allocator_surplus(
    rpc: &mut LightProgramTest,
    withdraw_authority: &Keypair,
    pool_allocator: Pubkey,
    recipient: Pubkey,
    lamports: u64,
    minimum_lamports_to_keep: u64,
) -> Result<Signature, RpcError> {
    let instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: vec![
            AccountMeta::new_readonly(withdraw_authority.pubkey(), true),
            AccountMeta::new(pool_allocator, false),
            AccountMeta::new(recipient, false),
        ],
        data: passkey_registry::instruction::WithdrawPoolAllocatorSurplus {
            lamports,
            minimum_lamports_to_keep,
        }
        .data(),
    };

    rpc.create_and_send_transaction(
        &[instruction],
        &withdraw_authority.pubkey(),
        &[withdraw_authority],
    )
    .await
}

async fn ensure_pool_allocator_light_config(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
) -> Result<(Pubkey, Pubkey), RpcError> {
    let config_bump = 0u16;
    let (compression_config, _) = Pubkey::find_program_address(
        &[light_account::LIGHT_CONFIG_SEED, &config_bump.to_le_bytes()],
        &passkey_registry::ID,
    );
    let (pda_rent_sponsor, _) = light_account::derive_rent_sponsor_pda(&passkey_registry::ID);

    if rpc.get_account(compression_config).await?.is_none() {
        let address_tree = rpc.get_address_tree_v2().tree;
        let instruction = Instruction {
            program_id: passkey_registry::ID,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(compression_config, false),
                AccountMeta::new_readonly(passkey_registry::ID, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            data: passkey_registry::instruction::InitializeCompressionConfig {
                params: passkey_registry::passkey_registry::InitConfigParams {
                    write_top_up: 0,
                    rent_sponsor: pda_rent_sponsor,
                    compression_authority: payer.pubkey(),
                    rent_config: light_account::RentConfig::default(),
                    address_space: vec![address_tree],
                },
            }
            .data(),
        };
        rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
            .await?;
    }
    if get_balance_or_zero(rpc, pda_rent_sponsor).await < 100_000_000 {
        rpc.airdrop_lamports(&pda_rent_sponsor, 100_000_000).await?;
    }

    Ok((compression_config, pda_rent_sponsor))
}

async fn initialize_pool_directory(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    pool_allocator: Pubkey,
    squads_settings: Pubkey,
    directory_address: &[u8; 32],
    active_pool_index: u128,
) -> Result<Signature, RpcError> {
    let mut remaining_accounts = PackedAccounts::default();
    remaining_accounts
        .add_system_accounts_v2(SystemAccountMetaConfig::new(passkey_registry::ID))?;

    let address_tree_info = rpc.get_address_tree_v2();
    let proof_result = rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address: *directory_address,
                tree: address_tree_info.tree,
            }],
            None,
        )
        .await?
        .value;
    let packed_accounts = proof_result.pack_tree_infos(&mut remaining_accounts);
    let output_state_tree_index = rpc
        .get_random_state_tree_info()?
        .pack_output_tree_index(&mut remaining_accounts)?;
    let (remaining_account_metas, _, _) = remaining_accounts.to_account_metas();

    let instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: [
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(pool_allocator, false),
                AccountMeta::new_readonly(squads_settings, false),
            ],
            remaining_account_metas,
        ]
        .concat(),
        data: passkey_registry::instruction::InitializePoolDirectory {
            proof: proof_result.proof,
            address_tree_info: packed_accounts.address_trees[0],
            output_state_tree_index,
            active_pool_index,
        }
        .data(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await
}

async fn provision_next_pool(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    current_pool_allocator: Pubkey,
    program_config: Pubkey,
    treasury: Pubkey,
    new_squads_settings: Pubkey,
    new_pool_allocator: Pubkey,
    directory_address: &[u8; 32],
    expected_active_pool_index: u128,
    next_allocator_lamports: u64,
) -> Result<Signature, RpcError> {
    let (compression_config, pda_rent_sponsor) =
        ensure_pool_allocator_light_config(rpc, payer).await?;
    let compressed_account = rpc
        .get_compressed_account(*directory_address, None)
        .await?
        .value
        .ok_or_else(|| RpcError::CustomError("missing compressed pool directory".to_string()))?;
    let current_directory = PoolDirectory::deserialize(
        &mut &compressed_account
            .data
            .as_ref()
            .ok_or_else(|| RpcError::CustomError("missing pool directory data".to_string()))?
            .data[..],
    )
    .map_err(|error| {
        RpcError::CustomError(format!("deserialize pool directory failed: {error}"))
    })?;

    let mut remaining_accounts = PackedAccounts::default();
    remaining_accounts
        .add_system_accounts_v2(SystemAccountMetaConfig::new(passkey_registry::ID))?;

    let address_tree_info = rpc.get_address_tree_v2();
    let light_pda_address = light_compressed_account::address::derive_address(
        &new_pool_allocator.to_bytes(),
        &address_tree_info.tree.to_bytes(),
        &passkey_registry::ID.to_bytes(),
    );
    let create_proof_result = rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address: light_pda_address,
                tree: address_tree_info.tree,
            }],
            None,
        )
        .await?
        .value;
    let create_packed_accounts = create_proof_result.pack_tree_infos(&mut remaining_accounts);
    let create_output_state_tree_index = rpc
        .get_random_state_tree_info()?
        .pack_output_tree_index(&mut remaining_accounts)?;

    let proof_result = rpc
        .get_validity_proof(vec![compressed_account.hash], vec![], None)
        .await?
        .value;
    let packed_accounts = proof_result.pack_tree_infos(&mut remaining_accounts);
    let state_trees = packed_accounts
        .state_trees
        .ok_or_else(|| RpcError::CustomError("missing state tree proof".to_string()))?;
    let account_meta = CompressedAccountMeta {
        tree_info: state_trees.packed_tree_infos[0],
        address: *directory_address,
        output_state_tree_index: state_trees.output_tree_index,
    };
    let (remaining_account_metas, _, _) = remaining_accounts.to_account_metas();

    let instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: [
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(compression_config, false),
                AccountMeta::new(pda_rent_sponsor, false),
                AccountMeta::new(current_pool_allocator, false),
                AccountMeta::new(program_config, false),
                AccountMeta::new(treasury, false),
                AccountMeta::new(new_squads_settings, false),
                AccountMeta::new(new_pool_allocator, false),
                AccountMeta::new_readonly(passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            remaining_account_metas,
        ]
        .concat(),
        data: passkey_registry::instruction::ProvisionNextPool {
            params: passkey_registry::ProvisionNextPoolParams {
                create_accounts_proof: light_account::CreateAccountsProof {
                    proof: create_proof_result.proof,
                    address_tree_info: create_packed_accounts.address_trees[0],
                    output_state_tree_index: create_output_state_tree_index,
                    state_tree_index: None,
                    system_accounts_offset: 0,
                },
                directory_proof: proof_result.proof,
                directory_account_meta: account_meta,
                expected_active_pool_index,
                current_directory,
                new_squads_settings,
                next_allocator_lamports,
            },
        }
        .data(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await
}

async fn fetch_pool_directory(
    rpc: &LightProgramTest,
    directory_address: [u8; 32],
) -> PoolDirectory {
    let compressed_account = rpc
        .get_compressed_account(directory_address, None)
        .await
        .unwrap()
        .value
        .unwrap();
    PoolDirectory::deserialize(&mut &compressed_account.data.as_ref().unwrap().data[..]).unwrap()
}

async fn fetch_passkey_authority(
    rpc: &LightProgramTest,
    authority_address: [u8; 32],
) -> PasskeyAuthority {
    let compressed_account = rpc
        .get_compressed_account(authority_address, None)
        .await
        .unwrap()
        .value
        .unwrap();
    PasskeyAuthority::deserialize(&mut &compressed_account.data.as_ref().unwrap().data[..]).unwrap()
}

async fn set_pool_allocator_next_index(
    rpc: &mut LightProgramTest,
    pool_allocator: Pubkey,
    next_index: u16,
) {
    let mut account = rpc.get_account(pool_allocator).await.unwrap().unwrap();
    let mut allocator = PoolAllocator::try_deserialize(&mut account.data.as_slice()).unwrap();
    allocator.next_index = next_index;

    let mut data = Vec::with_capacity(PoolAllocator::SPACE);
    allocator.try_serialize(&mut data).unwrap();
    account.data = data;
    rpc.context.set_account(pool_allocator, account).unwrap();
}

async fn get_balance_or_zero(rpc: &LightProgramTest, pubkey: Pubkey) -> u64 {
    rpc.get_account(pubkey)
        .await
        .unwrap()
        .map(|account| account.lamports)
        .unwrap_or_default()
}

async fn create_passkey_authority(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    authority: &Keypair,
    pool_allocator: solana_sdk::pubkey::Pubkey,
    address: &[u8; 32],
    assertion: TestWebAuthnAssertion,
    credential_id_hash: [u8; 32],
    passkey_pubkey_compressed: [u8; 33],
) -> Result<Signature, RpcError> {
    create_passkey_authority_with_instruction_order(
        rpc,
        payer,
        authority,
        pool_allocator,
        address,
        assertion,
        credential_id_hash,
        passkey_pubkey_compressed,
        0,
        true,
    )
    .await
}

async fn create_passkey_authority_with_instruction_order(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    authority: &Keypair,
    pool_allocator: solana_sdk::pubkey::Pubkey,
    address: &[u8; 32],
    assertion: TestWebAuthnAssertion,
    credential_id_hash: [u8; 32],
    passkey_pubkey_compressed: [u8; 33],
    secp256r1_instruction_index: u8,
    secp256r1_first: bool,
) -> Result<Signature, RpcError> {
    let passkey_pubkey_x: [u8; 32] = passkey_pubkey_compressed[1..].try_into().unwrap();

    let mut remaining_accounts = PackedAccounts::default();
    remaining_accounts
        .add_system_accounts_v2(SystemAccountMetaConfig::new(passkey_registry::ID))?;

    let address_tree_info = rpc.get_address_tree_v2();
    let proof_result = rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address: *address,
                tree: address_tree_info.tree,
            }],
            None,
        )
        .await?
        .value;
    let packed_accounts = proof_result.pack_tree_infos(&mut remaining_accounts);
    let output_state_tree_index = rpc
        .get_random_state_tree_info()?
        .pack_output_tree_index(&mut remaining_accounts)?;
    let (remaining_account_metas, _, _) = remaining_accounts.to_account_metas();

    let create_instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: [
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(pool_allocator, false),
                AccountMeta::new_readonly(sysvar::instructions::ID, false),
            ],
            remaining_account_metas,
        ]
        .concat(),
        data: passkey_registry::instruction::CreatePasskeyAuthority {
            proof: proof_result.proof,
            address_tree_info: packed_accounts.address_trees[0],
            output_state_tree_index,
            secp256r1_instruction_index,
            credential_id_hash,
            passkey_pubkey_prefix: passkey_pubkey_compressed[0],
            passkey_pubkey_x,
            authenticator_data: assertion.authenticator_data.clone(),
            client_data_json: assertion.client_data_json.clone(),
        }
        .data(),
    };

    let instructions = if secp256r1_first {
        vec![assertion.instruction, create_instruction]
    } else {
        vec![create_instruction, assertion.instruction]
    };

    rpc.create_and_send_transaction(&instructions, &payer.pubkey(), &[payer, authority])
        .await
}

async fn create_wallet_authority(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    authority: &Keypair,
    pool_allocator: Pubkey,
    address: &[u8; 32],
) -> Result<Signature, RpcError> {
    let mut remaining_accounts = PackedAccounts::default();
    remaining_accounts
        .add_system_accounts_v2(SystemAccountMetaConfig::new(passkey_registry::ID))?;

    let address_tree_info = rpc.get_address_tree_v2();
    let proof_result = rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address: *address,
                tree: address_tree_info.tree,
            }],
            None,
        )
        .await?
        .value;
    let packed_accounts = proof_result.pack_tree_infos(&mut remaining_accounts);
    let output_state_tree_index = rpc
        .get_random_state_tree_info()?
        .pack_output_tree_index(&mut remaining_accounts)?;
    let (remaining_account_metas, _, _) = remaining_accounts.to_account_metas();

    let instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: [
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(pool_allocator, false),
            ],
            remaining_account_metas,
        ]
        .concat(),
        data: passkey_registry::instruction::CreateWalletAuthority {
            proof: proof_result.proof,
            address_tree_info: packed_accounts.address_trees[0],
            output_state_tree_index,
        }
        .data(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer, authority])
        .await
}

fn create_passkey_signature_instruction(
    credential_id_hash: &[u8; 32],
    authority: &solana_sdk::pubkey::Pubkey,
    address_tree: &solana_sdk::pubkey::Pubkey,
    squads_settings: &solana_sdk::pubkey::Pubkey,
    vault_index: u8,
) -> ([u8; 33], TestWebAuthnAssertion) {
    let passkey = TestPasskey::new();
    let instruction = passkey.registration_instruction(
        credential_id_hash,
        authority,
        address_tree,
        squads_settings,
        vault_index,
    );

    (passkey.compressed_pubkey, instruction)
}

async fn create_squads_smart_account(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    verifier: Pubkey,
    seed: u128,
) -> Result<Pubkey, RpcError> {
    let squads_program_id = passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID;
    let program_config = derive_squads_program_config();
    let (settings, _) = Pubkey::find_program_address(
        &[
            passkey_registry::SQUADS_SEED_PREFIX,
            SQUADS_SETTINGS_SEED,
            &seed.to_le_bytes(),
        ],
        &squads_program_id,
    );
    let treasury = squads_treasury();
    let previous_smart_account_index = seed
        .checked_sub(1)
        .ok_or_else(|| RpcError::CustomError("Squads smart account seed must start at 1".into()))?;

    seed_squads_program_config(
        rpc,
        program_config,
        payer.pubkey(),
        treasury,
        previous_smart_account_index,
    )
    .await
    .unwrap();

    let mut data = Vec::from(SQUADS_CREATE_SMART_ACCOUNT_DISCRIMINATOR);
    serialize_squads_create_smart_account_args(&mut data, verifier).unwrap();
    let instruction = Instruction {
        program_id: squads_program_id,
        accounts: vec![
            AccountMeta::new(program_config, false),
            AccountMeta::new(treasury, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(squads_program_id, false),
            AccountMeta::new(settings, false),
        ],
        data,
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await?;

    Ok(settings)
}

fn derive_squads_program_config() -> Pubkey {
    Pubkey::find_program_address(
        &[
            passkey_registry::SQUADS_SEED_PREFIX,
            SQUADS_PROGRAM_CONFIG_SEED,
        ],
        &passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
    )
    .0
}

fn squads_treasury() -> Pubkey {
    Pubkey::new_from_array(hash32(b"loyal-test-squads-treasury"))
}

async fn seed_squads_program_config(
    rpc: &mut LightProgramTest,
    program_config: Pubkey,
    authority: Pubkey,
    treasury: Pubkey,
    smart_account_index: u128,
) -> Result<(), RpcError> {
    let mut data = Vec::with_capacity(160);
    data.extend_from_slice(&SQUADS_PROGRAM_CONFIG_DISCRIMINATOR);
    smart_account_index.serialize(&mut data).unwrap();
    authority.serialize(&mut data).unwrap();
    0u64.serialize(&mut data).unwrap();
    treasury.serialize(&mut data).unwrap();
    [0u8; 64].serialize(&mut data).unwrap();

    let lamports = rpc
        .get_minimum_balance_for_rent_exemption(data.len())
        .await?;
    rpc.context
        .set_account(
            program_config,
            Account {
                lamports,
                data,
                owner: passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .map_err(|error| RpcError::CustomError(format!("set program config failed: {error}")))?;

    Ok(())
}

async fn execute_passkey_vault_transfer(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    address: &[u8; 32],
    passkey: &TestPasskey,
    recipient: Pubkey,
    lamports: u64,
) -> Result<Signature, RpcError> {
    let compressed_account = rpc
        .get_compressed_account(*address, None)
        .await?
        .value
        .ok_or_else(|| RpcError::CustomError("missing compressed authority".to_string()))?;
    let current_authority = PasskeyAuthority::deserialize(
        &mut &compressed_account
            .data
            .as_ref()
            .ok_or_else(|| RpcError::CustomError("missing compressed authority data".to_string()))?
            .data[..],
    )
    .map_err(|error| RpcError::CustomError(format!("deserialize authority failed: {error}")))?;

    let (vault, _) = passkey_registry::derive_squads_vault(
        &current_authority.squads_settings,
        current_authority.vault_index,
    );
    let squads_payload = squads_system_transfer_payload(lamports);
    let squads_instruction_metas = vec![
        AccountMeta::new(vault, false),
        AccountMeta::new(recipient, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ];
    let squads_payload_hash = hashv(&[squads_payload.as_slice()]).to_bytes();
    let squads_accounts_hash = hash_squads_account_metas(&squads_instruction_metas);
    let expires_at_unix_timestamp = i64::MAX;
    let execution_challenge = passkey_registry::build_execution_challenge(
        &current_authority.credential_id_hash,
        current_authority.passkey_pubkey_prefix,
        &current_authority.passkey_pubkey_x,
        &current_authority.ed25519_authority,
        &current_authority.squads_settings,
        current_authority.vault_index,
        current_authority.nonce,
        expires_at_unix_timestamp,
        &squads_payload_hash,
        &squads_accounts_hash,
    );
    let assertion = passkey.signature_instruction(&execution_challenge);

    let mut remaining_accounts = PackedAccounts::default();
    remaining_accounts
        .add_system_accounts_v2(SystemAccountMetaConfig::new(passkey_registry::ID))?;
    let proof_result = rpc
        .get_validity_proof(vec![compressed_account.hash], vec![], None)
        .await?
        .value;
    let packed_accounts = proof_result.pack_tree_infos(&mut remaining_accounts);
    let state_trees = packed_accounts
        .state_trees
        .ok_or_else(|| RpcError::CustomError("missing state tree proof".to_string()))?;
    let account_meta = CompressedAccountMeta {
        tree_info: state_trees.packed_tree_infos[0],
        address: *address,
        output_state_tree_index: state_trees.output_tree_index,
    };
    let (light_remaining_account_metas, _, _) = remaining_accounts.to_account_metas();
    let light_remaining_accounts_count = light_remaining_account_metas.len() as u8;

    let execute_instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: [
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(current_authority.squads_settings, false),
                AccountMeta::new_readonly(passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID, false),
                AccountMeta::new_readonly(passkey_registry::derive_verifier_pda().0, false),
                AccountMeta::new_readonly(sysvar::instructions::ID, false),
            ],
            light_remaining_account_metas,
            squads_instruction_metas,
        ]
        .concat(),
        data: passkey_registry::instruction::ExecutePasskeyVaultTransaction {
            proof: proof_result.proof,
            account_meta,
            light_remaining_accounts_count,
            secp256r1_instruction_index: 0,
            expected_nonce: current_authority.nonce,
            expires_at_unix_timestamp,
            current_authority,
            squads_payload,
            authenticator_data: assertion.authenticator_data,
            client_data_json: assertion.client_data_json,
        }
        .data(),
    };

    rpc.create_and_send_transaction(
        &[assertion.instruction, execute_instruction],
        &payer.pubkey(),
        &[payer],
    )
    .await
}

async fn execute_wallet_vault_transfer(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    authority: &Keypair,
    address: &[u8; 32],
    recipient: Pubkey,
    lamports: u64,
) -> Result<Signature, RpcError> {
    let compressed_account = rpc
        .get_compressed_account(*address, None)
        .await?
        .value
        .ok_or_else(|| RpcError::CustomError("missing compressed authority".to_string()))?;
    let current_authority = PasskeyAuthority::deserialize(
        &mut &compressed_account
            .data
            .as_ref()
            .ok_or_else(|| RpcError::CustomError("missing compressed authority data".to_string()))?
            .data[..],
    )
    .map_err(|error| RpcError::CustomError(format!("deserialize authority failed: {error}")))?;

    let (vault, _) = passkey_registry::derive_squads_vault(
        &current_authority.squads_settings,
        current_authority.vault_index,
    );
    let squads_payload = squads_system_transfer_payload(lamports);
    let squads_instruction_metas = vec![
        AccountMeta::new(vault, false),
        AccountMeta::new(recipient, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ];

    let mut remaining_accounts = PackedAccounts::default();
    remaining_accounts
        .add_system_accounts_v2(SystemAccountMetaConfig::new(passkey_registry::ID))?;
    let proof_result = rpc
        .get_validity_proof(vec![compressed_account.hash], vec![], None)
        .await?
        .value;
    let packed_accounts = proof_result.pack_tree_infos(&mut remaining_accounts);
    let state_trees = packed_accounts
        .state_trees
        .ok_or_else(|| RpcError::CustomError("missing state tree proof".to_string()))?;
    let account_meta = CompressedAccountMeta {
        tree_info: state_trees.packed_tree_infos[0],
        address: *address,
        output_state_tree_index: state_trees.output_tree_index,
    };
    let (light_remaining_account_metas, _, _) = remaining_accounts.to_account_metas();
    let light_remaining_accounts_count = light_remaining_account_metas.len() as u8;

    let execute_instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: [
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(current_authority.squads_settings, false),
                AccountMeta::new_readonly(passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID, false),
                AccountMeta::new_readonly(passkey_registry::derive_verifier_pda().0, false),
            ],
            light_remaining_account_metas,
            squads_instruction_metas,
        ]
        .concat(),
        data: passkey_registry::instruction::ExecuteWalletVaultTransaction {
            proof: proof_result.proof,
            account_meta,
            light_remaining_accounts_count,
            expected_nonce: current_authority.nonce,
            current_authority,
            squads_payload,
        }
        .data(),
    };

    rpc.create_and_send_transaction(&[execute_instruction], &payer.pubkey(), &[payer, authority])
        .await
}

fn squads_system_transfer_payload(lamports: u64) -> Vec<u8> {
    let mut transfer_data =
        system_instruction::transfer(&Pubkey::default(), &Pubkey::default(), lamports).data;
    let mut payload = Vec::with_capacity(1 + 1 + 1 + 2 + transfer_data.len());
    payload.push(1);
    payload.push(2);
    payload.push(2);
    payload.push(0);
    payload.push(1);
    payload.extend_from_slice(&(transfer_data.len() as u16).to_le_bytes());
    payload.append(&mut transfer_data);
    payload
}

fn hash_squads_account_metas(accounts: &[AccountMeta]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(accounts.len() * 34);
    for account in accounts {
        bytes.extend_from_slice(account.pubkey.as_ref());
        bytes.push(u8::from(account.is_writable));
        bytes.push(u8::from(account.is_signer));
    }

    hashv(&[&bytes]).to_bytes()
}

struct TestPasskey {
    compressed_pubkey: [u8; 33],
    private_key_der: Vec<u8>,
}

struct TestWebAuthnAssertion {
    instruction: Instruction,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
}

impl TestPasskey {
    fn new() -> Self {
        let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let passkey = EcKey::generate(&curve).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let passkey_pubkey = passkey
            .public_key()
            .to_bytes(&curve, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        let passkey_pubkey_compressed: [u8; 33] = passkey_pubkey.try_into().unwrap();
        Self {
            compressed_pubkey: passkey_pubkey_compressed,
            private_key_der: passkey.private_key_to_der().unwrap(),
        }
    }

    fn registration_instruction(
        &self,
        credential_id_hash: &[u8; 32],
        authority: &Pubkey,
        address_tree: &Pubkey,
        squads_settings: &Pubkey,
        vault_index: u8,
    ) -> TestWebAuthnAssertion {
        let passkey_pubkey_x: [u8; 32] = self.compressed_pubkey[1..].try_into().unwrap();
        let challenge = build_registration_challenge(
            credential_id_hash,
            self.compressed_pubkey[0],
            &passkey_pubkey_x,
            authority,
            address_tree,
            squads_settings,
            vault_index,
        );
        assert_eq!(
            compressed_p256_pubkey(self.compressed_pubkey[0], &passkey_pubkey_x).unwrap(),
            self.compressed_pubkey
        );
        self.signature_instruction(&challenge)
    }

    fn signature_instruction(&self, challenge: &[u8]) -> TestWebAuthnAssertion {
        let authenticator_data = test_authenticator_data();
        let client_data_json = test_client_data_json(challenge);
        let client_data_hash = hashv(&[client_data_json.as_slice()]).to_bytes();
        let mut signed_message = Vec::with_capacity(authenticator_data.len() + 32);
        signed_message.extend_from_slice(&authenticator_data);
        signed_message.extend_from_slice(&client_data_hash);
        let signature =
            solana_secp256r1_program::sign_message(&signed_message, &self.private_key_der).unwrap();
        let instruction = solana_secp256r1_program::new_secp256r1_instruction_with_signature(
            &signed_message,
            &signature,
            &self.compressed_pubkey,
        );

        TestWebAuthnAssertion {
            instruction,
            authenticator_data,
            client_data_json,
        }
    }
}

fn test_authenticator_data() -> Vec<u8> {
    let mut data = vec![0u8; 37];
    data[32] = 0x05;
    data
}

fn test_client_data_json(challenge: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://passkey-work.test"}}"#,
        base64url_encode(challenge)
    )
    .into_bytes()
}

fn base64url_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut index = 0;

    while index + 3 <= input.len() {
        let chunk = ((input[index] as u32) << 16)
            | ((input[index + 1] as u32) << 8)
            | input[index + 2] as u32;
        output.push(TABLE[((chunk >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((chunk >> 12) & 0x3f) as usize] as char);
        output.push(TABLE[((chunk >> 6) & 0x3f) as usize] as char);
        output.push(TABLE[(chunk & 0x3f) as usize] as char);
        index += 3;
    }

    match input.len() - index {
        1 => {
            let chunk = (input[index] as u32) << 16;
            output.push(TABLE[((chunk >> 18) & 0x3f) as usize] as char);
            output.push(TABLE[((chunk >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let chunk = ((input[index] as u32) << 16) | ((input[index + 1] as u32) << 8);
            output.push(TABLE[((chunk >> 18) & 0x3f) as usize] as char);
            output.push(TABLE[((chunk >> 12) & 0x3f) as usize] as char);
            output.push(TABLE[((chunk >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }

    output
}

fn serialize_squads_create_smart_account_args(
    data: &mut Vec<u8>,
    verifier: Pubkey,
) -> std::io::Result<()> {
    Option::<Pubkey>::None.serialize(data)?;
    1u16.serialize(data)?;
    1u32.serialize(data)?;
    verifier.serialize(data)?;
    passkey_registry::SQUADS_FULL_PERMISSIONS_MASK.serialize(data)?;
    0u32.serialize(data)?;
    Option::<Pubkey>::None.serialize(data)?;
    Option::<String>::None.serialize(data)
}

fn prf_derived_authority() -> Keypair {
    Keypair::new_from_array(hash32(b"loyal-test-prf-output"))
}

fn hash32(value: &[u8]) -> [u8; 32] {
    hashv(&[value]).to_bytes()
}

fn install_light_cli_shim() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("passkey-registry should live under programs/");
    let cli_package = workspace_root.join("node_modules/@lightprotocol/zk-compression-cli");
    let cli_bin = workspace_root.join("node_modules/.bin/light");

    assert!(
        cli_package.exists() && cli_bin.exists(),
        "local Light CLI package must be installed before running SBF tests"
    );

    let shim_root = workspace_root.join("target/light-cli-shim");
    let shim_bin_dir = shim_root.join("bin");
    let shim_package_dir = shim_root.join("lib/node_modules/@lightprotocol");
    fs::create_dir_all(&shim_bin_dir).unwrap();
    fs::create_dir_all(&shim_package_dir).unwrap();

    replace_symlink(&cli_bin, &shim_bin_dir.join("light"));
    replace_symlink(&cli_package, &shim_package_dir.join("zk-compression-cli"));

    let path = env::var_os("PATH").unwrap_or_default();
    env::set_var(
        "PATH",
        format!("{}:{}", shim_bin_dir.display(), path.to_string_lossy()),
    );
}

fn replace_symlink(target: &Path, link: &Path) {
    let _ = fs::remove_file(link);
    let _ = fs::remove_dir(link);

    #[cfg(unix)]
    match std::os::unix::fs::symlink(target, link) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("failed to create Light CLI shim symlink: {error}"),
    }
}
const SQUADS_CREATE_SMART_ACCOUNT_DISCRIMINATOR: [u8; 8] = [197, 102, 253, 231, 77, 84, 50, 17];
const SQUADS_PROGRAM_CONFIG_DISCRIMINATOR: [u8; 8] = [196, 210, 90, 231, 144, 149, 140, 63];
const SQUADS_SMART_ACCOUNT_PROGRAM_NAME: &str = "squads_smart_account_program";
const SQUADS_PROGRAM_CONFIG_SEED: &[u8] = b"program_config";
const SQUADS_SETTINGS_SEED: &[u8] = b"settings";
