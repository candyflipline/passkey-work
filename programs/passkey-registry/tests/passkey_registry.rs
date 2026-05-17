#![cfg(feature = "test-sbf")]

use anchor_lang::{AccountDeserialize, AnchorDeserialize, AnchorSerialize, InstructionData};
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
    build_registration_challenge, compressed_p256_pubkey, PasskeyAuthority, PoolAllocator,
    PASSKEY_AUTHORITY_SEED, POOL_ALLOCATOR_SEED, POOL_ALLOCATOR_STATUS_ACTIVE,
    POOL_ALLOCATOR_VERSION,
};
use solana_sdk::{
    account::Account,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
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
        occupied_count: 0,
        bump: 255,
    };

    for expected_index in 0..=u8::MAX {
        assert_eq!(allocator.next_vault_index().unwrap(), expected_index);
        allocator.allocate_next(expected_index).unwrap();
    }

    assert_eq!(allocator.next_index, 256);
    assert_eq!(allocator.occupied_count, 256);
    assert!(allocator.next_vault_index().is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn creates_passkey_authority_compressed_pda() {
    let _guard = LIGHT_PROGRAM_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_light_cli_shim();

    let config =
        ProgramTestConfig::new_v2(true, Some(vec![("passkey_registry", passkey_registry::ID)]));
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let authority = prf_derived_authority();
    let squads_settings = Keypair::new().pubkey();
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
    assert_eq!(allocator.occupied_count, 1);
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

    let squads_settings = create_squads_smart_account(&mut rpc, &payer, verifier)
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

async fn initialize_pool_allocator(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    pool_allocator: solana_sdk::pubkey::Pubkey,
    squads_settings: solana_sdk::pubkey::Pubkey,
) -> Result<Signature, RpcError> {
    let instruction = Instruction {
        program_id: passkey_registry::ID,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(pool_allocator, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data: passkey_registry::instruction::InitializePoolAllocator { squads_settings }.data(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await
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
    secp256r1_instruction: Instruction,
    credential_id_hash: [u8; 32],
    passkey_pubkey_compressed: [u8; 33],
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
            secp256r1_instruction_index: 0,
            credential_id_hash,
            passkey_pubkey_prefix: passkey_pubkey_compressed[0],
            passkey_pubkey_x,
        }
        .data(),
    };

    rpc.create_and_send_transaction(
        &[secp256r1_instruction, create_instruction],
        &payer.pubkey(),
        &[payer, authority],
    )
    .await
}

fn create_passkey_signature_instruction(
    credential_id_hash: &[u8; 32],
    authority: &solana_sdk::pubkey::Pubkey,
    address_tree: &solana_sdk::pubkey::Pubkey,
    squads_settings: &solana_sdk::pubkey::Pubkey,
    vault_index: u8,
) -> ([u8; 33], Instruction) {
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
) -> Result<Pubkey, RpcError> {
    let squads_program_id = passkey_registry::SQUADS_SMART_ACCOUNT_PROGRAM_ID;
    let (program_config, _) = Pubkey::find_program_address(
        &[
            passkey_registry::SQUADS_SEED_PREFIX,
            SQUADS_PROGRAM_CONFIG_SEED,
        ],
        &squads_program_id,
    );
    let (settings, _) = Pubkey::find_program_address(
        &[
            passkey_registry::SQUADS_SEED_PREFIX,
            SQUADS_SETTINGS_SEED,
            &1u128.to_le_bytes(),
        ],
        &squads_program_id,
    );
    let treasury = Keypair::new().pubkey();

    seed_squads_program_config(rpc, program_config, payer.pubkey(), treasury)
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

async fn seed_squads_program_config(
    rpc: &mut LightProgramTest,
    program_config: Pubkey,
    authority: Pubkey,
    treasury: Pubkey,
) -> Result<(), RpcError> {
    let mut data = Vec::with_capacity(160);
    data.extend_from_slice(&SQUADS_PROGRAM_CONFIG_DISCRIMINATOR);
    0u128.serialize(&mut data).unwrap();
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
    let secp256r1_instruction = passkey.signature_instruction(&execution_challenge);

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
        }
        .data(),
    };

    rpc.create_and_send_transaction(
        &[secp256r1_instruction, execute_instruction],
        &payer.pubkey(),
        &[payer],
    )
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
    ) -> Instruction {
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

    fn signature_instruction(&self, challenge: &[u8]) -> Instruction {
        let signature =
            solana_secp256r1_program::sign_message(challenge, &self.private_key_der).unwrap();
        solana_secp256r1_program::new_secp256r1_instruction_with_signature(
            challenge,
            &signature,
            &self.compressed_pubkey,
        )
    }
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
