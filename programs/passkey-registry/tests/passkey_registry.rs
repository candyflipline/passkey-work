#![cfg(feature = "test-sbf")]

use anchor_lang::{AnchorDeserialize, InstructionData};
use light_program_test::{
    program_test::LightProgramTest, AddressWithTree, Indexer, ProgramTestConfig, Rpc, RpcError,
};
use light_sdk::{
    address::v2::derive_address,
    instruction::{PackedAccounts, SystemAccountMetaConfig},
};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
};
use passkey_registry::{
    build_registration_challenge, compressed_p256_pubkey, PasskeyAuthority, PASSKEY_AUTHORITY_SEED,
};
use solana_sdk::{
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signature, Signer},
    sysvar,
};
use std::{env, fs, path::Path};

#[test]
fn lite_svm_can_derive_the_prf_authority_signer() {
    let mut svm = litesvm::LiteSVM::new();
    let authority = prf_derived_authority();

    svm.airdrop(&authority.pubkey(), 1_000_000_000).unwrap();

    let account = svm.get_account(&authority.pubkey()).unwrap();
    assert_eq!(account.lamports, 1_000_000_000);
}

#[tokio::test]
async fn creates_passkey_authority_compressed_pda() {
    install_light_cli_shim();

    let config =
        ProgramTestConfig::new_v2(true, Some(vec![("passkey_registry", passkey_registry::ID)]));
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();
    let authority = prf_derived_authority();

    rpc.airdrop_lamports(&authority.pubkey(), 1_000_000_000)
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
    );

    create_passkey_authority(
        &mut rpc,
        &payer,
        &authority,
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
    assert_eq!(authority_record.nonce, 0);
}

async fn create_passkey_authority(
    rpc: &mut LightProgramTest,
    payer: &Keypair,
    authority: &Keypair,
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
) -> ([u8; 33], Instruction) {
    let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let passkey = EcKey::generate(&curve).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let passkey_pubkey = passkey
        .public_key()
        .to_bytes(&curve, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    let passkey_pubkey_compressed: [u8; 33] = passkey_pubkey.try_into().unwrap();
    let passkey_pubkey_x: [u8; 32] = passkey_pubkey_compressed[1..].try_into().unwrap();
    let challenge = build_registration_challenge(
        credential_id_hash,
        passkey_pubkey_compressed[0],
        &passkey_pubkey_x,
        authority,
        address_tree,
    );
    assert_eq!(
        compressed_p256_pubkey(passkey_pubkey_compressed[0], &passkey_pubkey_x).unwrap(),
        passkey_pubkey_compressed
    );
    let signature =
        solana_secp256r1_program::sign_message(&challenge, &passkey.private_key_to_der().unwrap())
            .unwrap();
    let instruction = solana_secp256r1_program::new_secp256r1_instruction_with_signature(
        &challenge,
        &signature,
        &passkey_pubkey_compressed,
    );

    (passkey_pubkey_compressed, instruction)
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

    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}
