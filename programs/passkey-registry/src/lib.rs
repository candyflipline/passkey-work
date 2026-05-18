#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};
use light_sdk::{
    account::LightAccount,
    address::v2::derive_address,
    cpi::{v2::CpiAccounts, CpiSigner},
    derive_light_cpi_signer,
    instruction::{account_meta::CompressedAccountMeta, PackedAddressTreeInfo, ValidityProof},
    LightDiscriminator, PackedAddressTreeInfoExt,
};
use light_sdk_types::ADDRESS_TREE_V2;

declare_id!("rTvZY3rX9PBXyWzHtMRnY92o7EiEFSwsYZKoCLxUY9X");

pub const PASSKEY_AUTHORITY_VERSION: u8 = 2;
pub const PASSKEY_AUTHORITY_STATUS_ACTIVE: u8 = 1;
pub const PASSKEY_AUTHORITY_SEED: &[u8] = b"passkey-authority";
pub const POOL_ALLOCATOR_VERSION: u8 = 1;
pub const POOL_ALLOCATOR_STATUS_ACTIVE: u8 = 1;
pub const POOL_ALLOCATOR_SEED: &[u8] = b"pool-allocator";
pub const POOL_DIRECTORY_VERSION: u8 = 1;
pub const POOL_DIRECTORY_STATUS_ACTIVE: u8 = 1;
pub const POOL_DIRECTORY_SEED: &[u8] = b"pool-directory";
pub const VERIFIER_SEED: &[u8] = b"passkey-verifier";
pub const REGISTRATION_DOMAIN: &[u8] = b"LOYAL_PASSKEY_REGISTER_V1";
pub const EXECUTION_DOMAIN: &[u8] = b"LOYAL_PASSKEY_EXECUTE_V1";
pub const SECP256R1_PROGRAM_ID: Pubkey = pubkey!("Secp256r1SigVerify1111111111111111111111111");
pub const SQUADS_SMART_ACCOUNT_PROGRAM_ID: Pubkey =
    pubkey!("SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG");
pub const SQUADS_SEED_PREFIX: &[u8] = b"smart_account";
pub const SQUADS_SEED_SMART_ACCOUNT: &[u8] = b"smart_account";
pub const SQUADS_EXECUTE_TRANSACTION_SYNC_V2_DISCRIMINATOR: [u8; 8] =
    [90, 81, 187, 81, 39, 70, 128, 78];
pub const SQUADS_SETTINGS_DISCRIMINATOR: [u8; 8] = [223, 179, 163, 190, 177, 224, 67, 173];
pub const SQUADS_FULL_PERMISSIONS_MASK: u8 = 7;
pub const SQUADS_SYNC_SIGNER_COUNT: u8 = 1;
pub const SQUADS_SEED_SETTINGS: &[u8] = b"settings";

// Light checks this program-authority PDA during CPI.
pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("rTvZY3rX9PBXyWzHtMRnY92o7EiEFSwsYZKoCLxUY9X");

#[program]
pub mod passkey_registry {
    use super::*;
    use light_sdk::cpi::{
        v2::LightSystemProgramCpi, InvokeLightSystemProgram, LightCpiInstruction,
    };

    pub fn create_passkey_authority<'info>(
        ctx: Context<'_, '_, '_, 'info, CreatePasskeyAuthority<'info>>,
        proof: ValidityProof,
        address_tree_info: PackedAddressTreeInfo,
        output_state_tree_index: u8,
        secp256r1_instruction_index: u8,
        credential_id_hash: [u8; 32],
        passkey_pubkey_prefix: u8,
        passkey_pubkey_x: [u8; 32],
    ) -> Result<()> {
        let light_cpi_accounts = CpiAccounts::new(
            ctx.accounts.authority.as_ref(),
            ctx.remaining_accounts,
            crate::LIGHT_CPI_SIGNER,
        );

        let address_tree_pubkey = address_tree_info
            .get_tree_pubkey(&light_cpi_accounts)
            .map_err(|_| error!(PasskeyRegistryError::InvalidAddressTree))?;

        if address_tree_pubkey.to_bytes() != ADDRESS_TREE_V2 {
            return err!(PasskeyRegistryError::InvalidAddressTree);
        }

        let passkey_pubkey_compressed =
            compressed_p256_pubkey(passkey_pubkey_prefix, &passkey_pubkey_x)?;

        // The allocator is the canonical source for the signed vault index.
        let squads_settings = ctx.accounts.pool_allocator.squads_settings;
        let vault_index = ctx.accounts.pool_allocator.next_vault_index()?;
        let registration_challenge = build_registration_challenge(
            &credential_id_hash,
            passkey_pubkey_prefix,
            &passkey_pubkey_x,
            &ctx.accounts.authority.key(),
            &address_tree_pubkey,
            &squads_settings,
            vault_index,
        );

        verify_secp256r1_instruction(
            ctx.accounts.instructions.as_ref(),
            secp256r1_instruction_index,
            &passkey_pubkey_compressed,
            &registration_challenge,
        )?;

        let (address, address_seed) = derive_address(
            &[PASSKEY_AUTHORITY_SEED, credential_id_hash.as_ref()],
            &address_tree_pubkey,
            &crate::ID,
        );

        let mut authority_record = LightAccount::<PasskeyAuthority>::new_init(
            &crate::ID,
            Some(address),
            output_state_tree_index,
        );
        authority_record.version = PASSKEY_AUTHORITY_VERSION;
        authority_record.status = PASSKEY_AUTHORITY_STATUS_ACTIVE;
        authority_record.credential_id_hash = credential_id_hash;
        authority_record.passkey_pubkey_prefix = passkey_pubkey_prefix;
        authority_record.passkey_pubkey_x = passkey_pubkey_x;
        authority_record.ed25519_authority = ctx.accounts.authority.key();
        authority_record.squads_settings = squads_settings;
        authority_record.vault_index = vault_index;
        authority_record.nonce = 0;

        // CPI atomicity.
        ctx.accounts.pool_allocator.allocate_next(vault_index)?;

        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, proof)
            .with_light_account(authority_record)?
            .with_new_addresses(&[
                address_tree_info.into_new_address_params_assigned_packed(address_seed, Some(0))
            ])
            .invoke(light_cpi_accounts)?;

        Ok(())
    }

    pub fn initialize_pool_allocator(ctx: Context<InitializePoolAllocator>) -> Result<()> {
        let squads_settings = ctx.accounts.squads_settings.key();
        let (verifier, _) = derive_verifier_pda();
        validate_squads_pool_settings(ctx.accounts.squads_settings.as_ref(), &verifier)?;

        let allocator = &mut ctx.accounts.pool_allocator;

        allocator.version = POOL_ALLOCATOR_VERSION;
        allocator.status = POOL_ALLOCATOR_STATUS_ACTIVE;
        allocator.squads_settings = squads_settings;
        allocator.next_index = 0;

        Ok(())
    }

    pub fn initialize_pool_directory<'info>(
        ctx: Context<'_, '_, '_, 'info, InitializePoolDirectory<'info>>,
        proof: ValidityProof,
        address_tree_info: PackedAddressTreeInfo,
        output_state_tree_index: u8,
        active_pool_index: u128,
    ) -> Result<()> {
        let light_cpi_accounts = CpiAccounts::new(
            ctx.accounts.payer.as_ref(),
            ctx.remaining_accounts,
            crate::LIGHT_CPI_SIGNER,
        );
        let address_tree_pubkey = address_tree_info
            .get_tree_pubkey(&light_cpi_accounts)
            .map_err(|_| error!(PasskeyRegistryError::InvalidAddressTree))?;

        if address_tree_pubkey.to_bytes() != ADDRESS_TREE_V2 {
            return err!(PasskeyRegistryError::InvalidAddressTree);
        }

        // Clients read the directory off chain before choosing the allocator.
        validate_active_pool_accounts(
            &ctx.accounts.pool_allocator,
            &ctx.accounts.squads_settings,
            active_pool_index,
        )?;

        let (address, address_seed) =
            derive_address(&[POOL_DIRECTORY_SEED], &address_tree_pubkey, &crate::ID);
        let mut pool_directory = LightAccount::<PoolDirectory>::new_init(
            &crate::ID,
            Some(address),
            output_state_tree_index,
        );
        pool_directory.version = POOL_DIRECTORY_VERSION;
        pool_directory.status = POOL_DIRECTORY_STATUS_ACTIVE;
        pool_directory.active_pool_index = active_pool_index;

        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, proof)
            .with_light_account(pool_directory)?
            .with_new_addresses(&[
                address_tree_info.into_new_address_params_assigned_packed(address_seed, Some(0))
            ])
            .invoke(light_cpi_accounts)?;

        Ok(())
    }

    pub fn advance_pool_directory<'info>(
        ctx: Context<'_, '_, '_, 'info, AdvancePoolDirectory<'info>>,
        proof: ValidityProof,
        account_meta: CompressedAccountMeta,
        expected_active_pool_index: u128,
        current_directory: PoolDirectory,
    ) -> Result<()> {
        // Rollover waits for all 256 vault indexes, so prepaid Squads capacity is never stranded.
        validate_current_pool_directory(
            &current_directory,
            &account_meta,
            expected_active_pool_index,
        )?;

        validate_exhausted_pool_allocator(
            &ctx.accounts.current_pool_allocator,
            current_directory.active_pool_index,
        )?;

        let next_pool_index = current_directory
            .active_pool_index
            .checked_add(1)
            .ok_or_else(|| error!(PasskeyRegistryError::PoolIndexOverflow))?;
        let (expected_next_settings, _) = derive_squads_settings(next_pool_index);
        if ctx.accounts.new_squads_settings.key() != expected_next_settings {
            return err!(PasskeyRegistryError::InvalidSquadsSettings);
        }

        let (verifier, _) = derive_verifier_pda();
        validate_squads_pool_settings(ctx.accounts.new_squads_settings.as_ref(), &verifier)?;

        let new_allocator = &mut ctx.accounts.new_pool_allocator;
        new_allocator.version = POOL_ALLOCATOR_VERSION;
        new_allocator.status = POOL_ALLOCATOR_STATUS_ACTIVE;
        new_allocator.squads_settings = ctx.accounts.new_squads_settings.key();
        new_allocator.next_index = 0;

        let mut pool_directory =
            LightAccount::<PoolDirectory>::new_mut(&crate::ID, &account_meta, current_directory)?;
        pool_directory.active_pool_index = next_pool_index;

        let light_cpi_accounts = CpiAccounts::new(
            ctx.accounts.payer.as_ref(),
            ctx.remaining_accounts,
            crate::LIGHT_CPI_SIGNER,
        );
        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, proof)
            .with_light_account(pool_directory)?
            .invoke(light_cpi_accounts)?;

        Ok(())
    }

    pub fn execute_passkey_vault_transaction<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecutePasskeyVaultTransaction<'info>>,
        proof: ValidityProof,
        account_meta: CompressedAccountMeta,
        light_remaining_accounts_count: u8,
        secp256r1_instruction_index: u8,
        expected_nonce: u64,
        expires_at_unix_timestamp: i64,
        current_authority: PasskeyAuthority,
        squads_payload: Vec<u8>,
    ) -> Result<()> {
        // Light proof accounts come first; the rest are forwarded to Squads unchanged.
        let (light_remaining_accounts, squads_instruction_accounts) = ctx
            .remaining_accounts
            .split_at_checked(usize::from(light_remaining_accounts_count))
            .ok_or_else(|| error!(PasskeyRegistryError::InvalidRemainingAccountsSplit))?;

        if Clock::get()?.unix_timestamp > expires_at_unix_timestamp {
            return err!(PasskeyRegistryError::ExpiredExecutionChallenge);
        }

        validate_current_authority(
            &current_authority,
            &account_meta,
            &ctx.accounts.squads_settings.key(),
            expected_nonce,
        )?;
        validate_squads_pool_settings(
            ctx.accounts.squads_settings.as_ref(),
            &ctx.accounts.verifier.key(),
        )?;

        let passkey_pubkey_compressed = compressed_p256_pubkey(
            current_authority.passkey_pubkey_prefix,
            &current_authority.passkey_pubkey_x,
        )?;
        // The passkey signs both payload bytes and metas, so callers cannot swap accounts.
        let squads_payload_hash = hashv(&[squads_payload.as_slice()]).to_bytes();
        let squads_accounts_hash = hash_squads_instruction_accounts(squads_instruction_accounts);
        let execution_challenge = build_execution_challenge(
            &current_authority.credential_id_hash,
            current_authority.passkey_pubkey_prefix,
            &current_authority.passkey_pubkey_x,
            &current_authority.ed25519_authority,
            &current_authority.squads_settings,
            current_authority.vault_index,
            expected_nonce,
            expires_at_unix_timestamp,
            &squads_payload_hash,
            &squads_accounts_hash,
        );

        verify_secp256r1_instruction(
            ctx.accounts.instructions.as_ref(),
            secp256r1_instruction_index,
            &passkey_pubkey_compressed,
            &execution_challenge,
        )?;

        let account_index = current_authority.vault_index;
        let mut authority_record = LightAccount::<PasskeyAuthority>::new_mut(
            &crate::ID,
            &account_meta,
            current_authority,
        )?;
        authority_record.nonce = authority_record
            .nonce
            .checked_add(1)
            .ok_or_else(|| error!(PasskeyRegistryError::NonceOverflow))?;

        let light_cpi_accounts = CpiAccounts::new(
            ctx.accounts.payer.as_ref(),
            light_remaining_accounts,
            crate::LIGHT_CPI_SIGNER,
        );
        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, proof)
            .with_light_account(authority_record)?
            .invoke(light_cpi_accounts)?;

        invoke_squads_sync_transaction(
            &ctx.accounts.squads_settings,
            &ctx.accounts.squads_program,
            &ctx.accounts.verifier,
            squads_instruction_accounts,
            account_index,
            squads_payload,
            ctx.bumps.verifier,
        )?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializePoolAllocator<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: validated as a static Squads settings account before storing the pool.
    pub squads_settings: UncheckedAccount<'info>,
    #[account(
        init,
        payer = payer,
        space = PoolAllocator::SPACE,
        seeds = [POOL_ALLOCATOR_SEED, squads_settings.key().as_ref()],
        bump
    )]
    pub pool_allocator: Account<'info, PoolAllocator>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreatePasskeyAuthority<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        constraint = pool_allocator.version == POOL_ALLOCATOR_VERSION,
        constraint = pool_allocator.status == POOL_ALLOCATOR_STATUS_ACTIVE
    )]
    pub pool_allocator: Account<'info, PoolAllocator>,
    /// CHECK: constrained to the instructions sysvar address.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct InitializePoolDirectory<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        constraint = pool_allocator.version == POOL_ALLOCATOR_VERSION,
        constraint = pool_allocator.status == POOL_ALLOCATOR_STATUS_ACTIVE
    )]
    pub pool_allocator: Account<'info, PoolAllocator>,
    /// CHECK: validated against the supplied pool index and Squads settings shape.
    pub squads_settings: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AdvancePoolDirectory<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        constraint = current_pool_allocator.version == POOL_ALLOCATOR_VERSION,
        constraint = current_pool_allocator.status == POOL_ALLOCATOR_STATUS_ACTIVE
    )]
    pub current_pool_allocator: Account<'info, PoolAllocator>,
    /// CHECK: validated as the next deterministic Squads settings account.
    pub new_squads_settings: UncheckedAccount<'info>,
    #[account(
        init,
        payer = payer,
        space = PoolAllocator::SPACE,
        seeds = [POOL_ALLOCATOR_SEED, new_squads_settings.key().as_ref()],
        bump
    )]
    pub new_pool_allocator: Account<'info, PoolAllocator>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecutePasskeyVaultTransaction<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: the compressed authority record stores the expected settings key.
    #[account(mut)]
    pub squads_settings: UncheckedAccount<'info>,
    /// CHECK: constrained to the Squads smart account program id.
    #[account(address = SQUADS_SMART_ACCOUNT_PROGRAM_ID)]
    pub squads_program: UncheckedAccount<'info>,
    /// CHECK: PDA signer used as the sole Squads member.
    #[account(seeds = [VERIFIER_SEED], bump)]
    pub verifier: UncheckedAccount<'info>,
    /// CHECK: constrained to the instructions sysvar address.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
}

/// Hot, rent-paid state for the next vault index in one Squads settings pool.
#[account]
#[derive(Debug, Default)]
pub struct PoolAllocator {
    pub version: u8,
    pub status: u8,
    pub squads_settings: Pubkey,
    pub next_index: u16,
}

impl PoolAllocator {
    pub const SPACE: usize = 8 + 1 + 1 + 32 + 2;

    pub fn next_vault_index(&self) -> Result<u8> {
        if self.next_index > u16::from(u8::MAX) {
            return err!(PasskeyRegistryError::PoolExhausted);
        }

        Ok(self.next_index as u8)
    }

    pub fn allocate_next(&mut self, expected_index: u8) -> Result<()> {
        let next_index = self.next_vault_index()?;
        if next_index != expected_index {
            return err!(PasskeyRegistryError::AllocatorIndexChanged);
        }

        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| error!(PasskeyRegistryError::PoolExhausted))?;
        Ok(())
    }

    pub fn is_exhausted(&self) -> bool {
        self.next_index > u16::from(u8::MAX)
    }
}

/// Compressed cursor pointing clients to the active Squads settings seed without scanning old allocators.
#[event]
#[derive(Clone, Debug, Default, LightDiscriminator)]
pub struct PoolDirectory {
    pub version: u8,
    pub status: u8,
    pub active_pool_index: u128,
}

/// Per-passkey compressed authority record that stores the vault binding only.
#[event]
#[derive(Clone, Debug, Default, LightDiscriminator)]
pub struct PasskeyAuthority {
    pub version: u8,
    pub status: u8,
    pub credential_id_hash: [u8; 32],
    pub passkey_pubkey_prefix: u8,
    pub passkey_pubkey_x: [u8; 32],
    pub ed25519_authority: Pubkey,
    pub squads_settings: Pubkey,
    pub vault_index: u8,
    pub nonce: u64,
}

pub fn build_registration_challenge(
    credential_id_hash: &[u8; 32],
    passkey_pubkey_prefix: u8,
    passkey_pubkey_x: &[u8; 32],
    ed25519_authority: &Pubkey,
    address_tree: &Pubkey,
    squads_settings: &Pubkey,
    vault_index: u8,
) -> Vec<u8> {
    let mut challenge = Vec::with_capacity(
        REGISTRATION_DOMAIN.len() + 32 + 32 + 32 + 33 + 32 + 32 + 1 + core::mem::size_of::<u64>(),
    );

    challenge.extend_from_slice(REGISTRATION_DOMAIN);
    challenge.extend_from_slice(crate::ID.as_ref());
    challenge.extend_from_slice(ed25519_authority.as_ref());
    challenge.extend_from_slice(credential_id_hash);
    challenge.push(passkey_pubkey_prefix);
    challenge.extend_from_slice(passkey_pubkey_x);
    challenge.extend_from_slice(address_tree.as_ref());
    challenge.extend_from_slice(squads_settings.as_ref());
    challenge.push(vault_index);
    challenge.extend_from_slice(&0u64.to_le_bytes());
    challenge
}

pub fn build_execution_challenge(
    credential_id_hash: &[u8; 32],
    passkey_pubkey_prefix: u8,
    passkey_pubkey_x: &[u8; 32],
    ed25519_authority: &Pubkey,
    squads_settings: &Pubkey,
    vault_index: u8,
    nonce: u64,
    expires_at_unix_timestamp: i64,
    squads_payload_hash: &[u8; 32],
    squads_accounts_hash: &[u8; 32],
) -> Vec<u8> {
    let (verifier, _) = derive_verifier_pda();
    let mut challenge = Vec::with_capacity(
        EXECUTION_DOMAIN.len()
            + 32
            + 32
            + 32
            + 32
            + 32
            + 33
            + 32
            + 1
            + core::mem::size_of::<u64>()
            + core::mem::size_of::<i64>()
            + 32
            + 32,
    );

    challenge.extend_from_slice(EXECUTION_DOMAIN);
    challenge.extend_from_slice(crate::ID.as_ref());
    challenge.extend_from_slice(SQUADS_SMART_ACCOUNT_PROGRAM_ID.as_ref());
    challenge.extend_from_slice(verifier.as_ref());
    challenge.extend_from_slice(ed25519_authority.as_ref());
    challenge.extend_from_slice(credential_id_hash);
    challenge.push(passkey_pubkey_prefix);
    challenge.extend_from_slice(passkey_pubkey_x);
    challenge.extend_from_slice(squads_settings.as_ref());
    challenge.push(vault_index);
    challenge.extend_from_slice(&nonce.to_le_bytes());
    challenge.extend_from_slice(&expires_at_unix_timestamp.to_le_bytes());
    challenge.extend_from_slice(squads_payload_hash);
    challenge.extend_from_slice(squads_accounts_hash);
    challenge
}

pub fn derive_verifier_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[VERIFIER_SEED], &crate::ID)
}

pub fn derive_squads_settings(pool_index: u128) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            SQUADS_SEED_PREFIX,
            SQUADS_SEED_SETTINGS,
            &pool_index.to_le_bytes(),
        ],
        &SQUADS_SMART_ACCOUNT_PROGRAM_ID,
    )
}

pub fn derive_squads_vault(squads_settings: &Pubkey, vault_index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            SQUADS_SEED_PREFIX,
            squads_settings.as_ref(),
            SQUADS_SEED_SMART_ACCOUNT,
            &[vault_index],
        ],
        &SQUADS_SMART_ACCOUNT_PROGRAM_ID,
    )
}

pub fn compressed_p256_pubkey(prefix: u8, x: &[u8; 32]) -> Result<[u8; 33]> {
    if prefix != 2 && prefix != 3 {
        return err!(PasskeyRegistryError::InvalidPasskeyPublicKey);
    }

    let mut pubkey = [0u8; 33];
    pubkey[0] = prefix;
    pubkey[1..].copy_from_slice(x);
    Ok(pubkey)
}

fn validate_current_authority(
    authority: &PasskeyAuthority,
    account_meta: &CompressedAccountMeta,
    squads_settings: &Pubkey,
    expected_nonce: u64,
) -> Result<()> {
    if authority.version != PASSKEY_AUTHORITY_VERSION
        || authority.status != PASSKEY_AUTHORITY_STATUS_ACTIVE
    {
        return err!(PasskeyRegistryError::InactivePasskeyAuthority);
    }

    if &authority.squads_settings != squads_settings {
        return err!(PasskeyRegistryError::InvalidSquadsSettings);
    }

    if authority.nonce != expected_nonce {
        return err!(PasskeyRegistryError::InvalidNonce);
    }

    let address_tree = Pubkey::new_from_array(ADDRESS_TREE_V2);
    let (expected_address, _) = derive_address(
        &[
            PASSKEY_AUTHORITY_SEED,
            authority.credential_id_hash.as_ref(),
        ],
        &address_tree,
        &crate::ID,
    );

    if account_meta.address != expected_address {
        return err!(PasskeyRegistryError::InvalidPasskeyAuthorityAddress);
    }

    Ok(())
}

fn validate_active_pool_accounts(
    allocator: &Account<'_, PoolAllocator>,
    squads_settings: &UncheckedAccount<'_>,
    pool_index: u128,
) -> Result<()> {
    let (expected_settings, _) = derive_squads_settings(pool_index);
    if squads_settings.key() != expected_settings || allocator.squads_settings != expected_settings
    {
        return err!(PasskeyRegistryError::InvalidSquadsSettings);
    }

    let (expected_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, expected_settings.as_ref()],
        &crate::ID,
    );
    if allocator.key() != expected_allocator {
        return err!(PasskeyRegistryError::InvalidPoolAllocator);
    }

    let (verifier, _) = derive_verifier_pda();
    validate_squads_pool_settings(squads_settings.as_ref(), &verifier)
}

fn validate_exhausted_pool_allocator(
    allocator: &Account<'_, PoolAllocator>,
    active_pool_index: u128,
) -> Result<()> {
    let (expected_settings, _) = derive_squads_settings(active_pool_index);
    if allocator.squads_settings != expected_settings {
        return err!(PasskeyRegistryError::InvalidSquadsSettings);
    }

    let (expected_allocator, _) = Pubkey::find_program_address(
        &[POOL_ALLOCATOR_SEED, expected_settings.as_ref()],
        &crate::ID,
    );
    if allocator.key() != expected_allocator {
        return err!(PasskeyRegistryError::InvalidPoolAllocator);
    }

    if !allocator.is_exhausted() {
        return err!(PasskeyRegistryError::PoolStillHasCapacity);
    }

    Ok(())
}

fn validate_current_pool_directory(
    directory: &PoolDirectory,
    account_meta: &CompressedAccountMeta,
    expected_active_pool_index: u128,
) -> Result<()> {
    if directory.version != POOL_DIRECTORY_VERSION
        || directory.status != POOL_DIRECTORY_STATUS_ACTIVE
    {
        return err!(PasskeyRegistryError::InactivePoolDirectory);
    }

    if directory.active_pool_index != expected_active_pool_index {
        return err!(PasskeyRegistryError::PoolDirectoryIndexChanged);
    }

    let address_tree = Pubkey::new_from_array(ADDRESS_TREE_V2);
    let (expected_address, _) = derive_address(&[POOL_DIRECTORY_SEED], &address_tree, &crate::ID);
    if account_meta.address != expected_address {
        return err!(PasskeyRegistryError::InvalidPoolDirectoryAddress);
    }

    Ok(())
}

fn validate_squads_pool_settings(
    settings_account: &AccountInfo<'_>,
    verifier: &Pubkey,
) -> Result<()> {
    if settings_account.owner != &SQUADS_SMART_ACCOUNT_PROGRAM_ID {
        return err!(PasskeyRegistryError::InvalidSquadsSettings);
    }

    let data = settings_account.try_borrow_data()?;
    if data.len() < 8 || data[..8] != SQUADS_SETTINGS_DISCRIMINATOR {
        return err!(PasskeyRegistryError::InvalidSquadsSettings);
    }

    let mut body = &data[8..];
    let settings = SquadsSettingsView::deserialize(&mut body)
        .map_err(|_| error!(PasskeyRegistryError::InvalidSquadsSettings))?;

    // Pool settings must stay static: one verifier signer, no time lock, no authority.
    if settings.settings_authority != Pubkey::default()
        || settings.threshold != 1
        || settings.time_lock != 0
        || settings.signers.len() != 1
    {
        return err!(PasskeyRegistryError::InvalidSquadsSettings);
    }

    let signer = &settings.signers[0];
    if signer.key != *verifier || signer.permissions.mask != SQUADS_FULL_PERMISSIONS_MASK {
        return err!(PasskeyRegistryError::InvalidSquadsSettings);
    }

    Ok(())
}

fn invoke_squads_sync_transaction<'info>(
    squads_settings: &UncheckedAccount<'info>,
    squads_program: &UncheckedAccount<'info>,
    verifier: &UncheckedAccount<'info>,
    squads_instruction_accounts: &[AccountInfo<'info>],
    account_index: u8,
    squads_payload: Vec<u8>,
    verifier_bump: u8,
) -> Result<()> {
    let args = SquadsSyncTransactionArgs {
        account_index,
        num_signers: SQUADS_SYNC_SIGNER_COUNT,
        payload: SquadsSyncPayload::Transaction(squads_payload),
    };
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&SQUADS_EXECUTE_TRANSACTION_SYNC_V2_DISCRIMINATOR);
    args.serialize(&mut data)
        .map_err(|_| error!(PasskeyRegistryError::InvalidSquadsSyncPayload))?;

    let mut accounts = Vec::with_capacity(3 + squads_instruction_accounts.len());
    accounts.push(AccountMeta::new(squads_settings.key(), false));
    accounts.push(AccountMeta::new_readonly(squads_program.key(), false));
    accounts.push(AccountMeta::new_readonly(verifier.key(), true));
    accounts.extend(
        squads_instruction_accounts
            .iter()
            .map(account_meta_from_info),
    );

    let instruction = Instruction {
        program_id: squads_program.key(),
        accounts,
        data,
    };

    let mut account_infos = Vec::with_capacity(3 + squads_instruction_accounts.len());
    account_infos.push(squads_settings.to_account_info());
    account_infos.push(squads_program.to_account_info());
    account_infos.push(verifier.to_account_info());
    account_infos.extend(squads_instruction_accounts.iter().cloned());

    let verifier_bump_seed = [verifier_bump];
    let signer_seeds: &[&[u8]] = &[VERIFIER_SEED, &verifier_bump_seed];
    invoke_signed(&instruction, &account_infos, &[signer_seeds])?;

    Ok(())
}

fn account_meta_from_info(account: &AccountInfo<'_>) -> AccountMeta {
    if account.is_writable {
        AccountMeta::new(account.key(), account.is_signer)
    } else {
        AccountMeta::new_readonly(account.key(), account.is_signer)
    }
}

fn hash_squads_instruction_accounts(accounts: &[AccountInfo<'_>]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(accounts.len() * 34);
    for account in accounts {
        bytes.extend_from_slice(account.key.as_ref());
        bytes.push(u8::from(account.is_writable));
        bytes.push(u8::from(account.is_signer));
    }

    hashv(&[&bytes]).to_bytes()
}

fn verify_secp256r1_instruction(
    instructions: &AccountInfo<'_>,
    instruction_index: u8,
    expected_pubkey: &[u8; 33],
    expected_message: &[u8],
) -> Result<()> {
    // The precompile verifies the signature; this binds it to our expected key and message.
    let current_instruction_index = load_current_index_checked(instructions)
        .map_err(|_| error!(PasskeyRegistryError::InvalidSecp256r1Instruction))?;
    if u16::from(instruction_index) >= current_instruction_index {
        return err!(PasskeyRegistryError::Secp256r1InstructionMustPrecedeRegistry);
    }

    let instruction = load_instruction_at_checked(instruction_index as usize, instructions)
        .map_err(|_| error!(PasskeyRegistryError::MissingSecp256r1Instruction))?;

    if instruction.program_id != SECP256R1_PROGRAM_ID {
        return err!(PasskeyRegistryError::MissingSecp256r1Instruction);
    }

    let data = instruction.data.as_slice();
    if data.len() < 16 || data[0] != 1 {
        return err!(PasskeyRegistryError::InvalidSecp256r1Instruction);
    }

    let signature_offset = read_u16(data, 2)? as usize;
    let signature_instruction_index = read_u16(data, 4)?;
    let public_key_offset = read_u16(data, 6)? as usize;
    let public_key_instruction_index = read_u16(data, 8)?;
    let message_data_offset = read_u16(data, 10)? as usize;
    let message_data_size = read_u16(data, 12)? as usize;
    let message_instruction_index = read_u16(data, 14)?;

    if signature_instruction_index != u16::MAX
        || public_key_instruction_index != u16::MAX
        || message_instruction_index != u16::MAX
    {
        return err!(PasskeyRegistryError::InvalidSecp256r1Instruction);
    }

    let public_key_end = public_key_offset
        .checked_add(33)
        .ok_or_else(|| error!(PasskeyRegistryError::InvalidSecp256r1Instruction))?;
    let signature_end = signature_offset
        .checked_add(64)
        .ok_or_else(|| error!(PasskeyRegistryError::InvalidSecp256r1Instruction))?;
    let message_end = message_data_offset
        .checked_add(message_data_size)
        .ok_or_else(|| error!(PasskeyRegistryError::InvalidSecp256r1Instruction))?;

    if public_key_end > data.len() || signature_end > data.len() || message_end > data.len() {
        return err!(PasskeyRegistryError::InvalidSecp256r1Instruction);
    }

    if &data[public_key_offset..public_key_end] != expected_pubkey {
        return err!(PasskeyRegistryError::InvalidPasskeyPublicKey);
    }

    if message_data_size != expected_message.len()
        || &data[message_data_offset..message_end] != expected_message
    {
        return err!(PasskeyRegistryError::InvalidRegistrationChallenge);
    }

    Ok(())
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| error!(PasskeyRegistryError::InvalidSecp256r1Instruction))?;

    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum SquadsSyncPayload {
    Transaction(Vec<u8>),
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SquadsSyncTransactionArgs {
    pub account_index: u8,
    pub num_signers: u8,
    pub payload: SquadsSyncPayload,
}

#[derive(AnchorDeserialize)]
struct SquadsSettingsView {
    _seed: u128,
    settings_authority: Pubkey,
    threshold: u16,
    time_lock: u32,
    _transaction_index: u64,
    _stale_transaction_index: u64,
    _archival_authority: Option<Pubkey>,
    _archivable_after: u64,
    _bump: u8,
    signers: Vec<SquadsSmartAccountSignerView>,
    _account_utilization: u8,
    _policy_seed: Option<u64>,
    _reserved2: u8,
}

#[derive(AnchorDeserialize)]
struct SquadsSmartAccountSignerView {
    key: Pubkey,
    permissions: SquadsPermissionsView,
}

#[derive(AnchorDeserialize)]
struct SquadsPermissionsView {
    mask: u8,
}

#[error_code]
pub enum PasskeyRegistryError {
    #[msg("The packed Light address tree is not the expected tree")]
    InvalidAddressTree,
    #[msg("Missing secp256r1 verification instruction")]
    MissingSecp256r1Instruction,
    #[msg("Invalid secp256r1 verification instruction data")]
    InvalidSecp256r1Instruction,
    #[msg("The passkey public key does not match the verified secp256r1 instruction")]
    InvalidPasskeyPublicKey,
    #[msg("The registration challenge does not match the verified secp256r1 instruction")]
    InvalidRegistrationChallenge,
    #[msg("The Squads vault pool is exhausted")]
    PoolExhausted,
    #[msg("The pool allocator PDA does not match the supplied Squads settings account")]
    InvalidPoolAllocator,
    #[msg("The current Squads vault pool still has free vault indexes")]
    PoolStillHasCapacity,
    #[msg("The pool directory index overflowed")]
    PoolIndexOverflow,
    #[msg("The pool directory is not active")]
    InactivePoolDirectory,
    #[msg("The compressed pool directory address does not match the expected cursor")]
    InvalidPoolDirectoryAddress,
    #[msg("The active pool index changed before the pool directory could advance")]
    PoolDirectoryIndexChanged,
    #[msg("The allocator index changed before the passkey authority could be created")]
    AllocatorIndexChanged,
    #[msg("The passkey authority is not active")]
    InactivePasskeyAuthority,
    #[msg("The compressed passkey authority address does not match the credential")]
    InvalidPasskeyAuthorityAddress,
    #[msg("The passkey authority does not belong to the supplied Squads settings account")]
    InvalidSquadsSettings,
    #[msg("The passkey authority nonce does not match the expected nonce")]
    InvalidNonce,
    #[msg("The passkey authority nonce overflowed")]
    NonceOverflow,
    #[msg("The execution challenge has expired")]
    ExpiredExecutionChallenge,
    #[msg("The remaining accounts split does not match the supplied Light account count")]
    InvalidRemainingAccountsSplit,
    #[msg("The Squads synchronous transaction payload could not be serialized")]
    InvalidSquadsSyncPayload,
    #[msg("The secp256r1 verification instruction must precede the registry instruction")]
    Secp256r1InstructionMustPrecedeRegistry,
}
