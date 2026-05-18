#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};
use light_account::{light_program, CompressionInfo, CreateAccountsProof, LightAccounts};
use light_sdk::{
    account::LightAccount as CompressedLightAccount,
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
pub const SQUADS_CREATE_SMART_ACCOUNT_DISCRIMINATOR: [u8; 8] = [197, 102, 253, 231, 77, 84, 50, 17];
pub const SQUADS_SETTINGS_DISCRIMINATOR: [u8; 8] = [223, 179, 163, 190, 177, 224, 67, 173];
pub const SQUADS_FULL_PERMISSIONS_MASK: u8 = 7;
pub const SQUADS_SYNC_SIGNER_COUNT: u8 = 1;
pub const SQUADS_SEED_SETTINGS: &[u8] = b"settings";
pub const SQUADS_PROGRAM_CONFIG_SEED: &[u8] = b"program_config";
pub const SQUADS_ONE_SIGNER_SETTINGS_SPACE: usize = 168;
pub const WEBAUTHN_GET_TYPE: &[u8] = b"webauthn.get";
pub const WEBAUTHN_MAX_AUTHENTICATOR_DATA_LEN: usize = 512;
pub const WEBAUTHN_MAX_CLIENT_DATA_JSON_LEN: usize = 2048;

// Light checks this program-authority PDA during CPI.
pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("rTvZY3rX9PBXyWzHtMRnY92o7EiEFSwsYZKoCLxUY9X");

#[light_program]
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
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
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

        verify_webauthn_secp256r1_instruction(
            ctx.accounts.instructions.as_ref(),
            secp256r1_instruction_index,
            &passkey_pubkey_compressed,
            &registration_challenge,
            &authenticator_data,
            &client_data_json,
        )?;

        let (address, address_seed) = derive_address(
            &[PASSKEY_AUTHORITY_SEED, credential_id_hash.as_ref()],
            &address_tree_pubkey,
            &crate::ID,
        );

        let mut authority_record = CompressedLightAccount::<PasskeyAuthority>::new_init(
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

    pub fn initialize_pool_allocator<'info>(
        ctx: Context<'_, '_, '_, 'info, InitializePoolAllocator<'info>>,
        params: InitializePoolAllocatorParams,
    ) -> Result<()> {
        let squads_settings = ctx.accounts.squads_settings.key();
        if params.squads_settings != squads_settings {
            return err!(PasskeyRegistryError::InvalidSquadsSettings);
        }

        let (verifier, _) = derive_verifier_pda();
        validate_squads_pool_settings(ctx.accounts.squads_settings.as_ref(), &verifier)?;

        let allocator = &mut ctx.accounts.pool_allocator;

        allocator.version = POOL_ALLOCATOR_VERSION;
        allocator.status = POOL_ALLOCATOR_STATUS_ACTIVE;
        allocator.squads_settings = squads_settings;
        allocator.next_index = 0;
        allocator.bump = ctx.bumps.pool_allocator;
        allocator.withdraw_authority = params.withdraw_authority;

        Ok(())
    }

    pub fn fund_pool_allocator(ctx: Context<FundPoolAllocator>, lamports: u64) -> Result<()> {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.funder.to_account_info(),
                    to: ctx.accounts.pool_allocator.to_account_info(),
                },
            ),
            lamports,
        )?;

        Ok(())
    }

    pub fn withdraw_pool_allocator_surplus(
        ctx: Context<WithdrawPoolAllocatorSurplus>,
        lamports: u64,
        minimum_lamports_to_keep: u64,
    ) -> Result<()> {
        if ctx.accounts.withdraw_authority.key() != ctx.accounts.pool_allocator.withdraw_authority {
            return err!(PasskeyRegistryError::UnauthorizedPoolAllocatorWithdrawal);
        }

        let remaining = ctx
            .accounts
            .pool_allocator
            .to_account_info()
            .lamports()
            .checked_sub(lamports)
            .ok_or_else(|| error!(PasskeyRegistryError::InsufficientPoolAllocatorLamports))?;
        if remaining < minimum_lamports_to_keep {
            return err!(PasskeyRegistryError::InsufficientPoolAllocatorLamports);
        }

        transfer_lamports_from_owned_account(
            &ctx.accounts.pool_allocator.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            lamports,
        )?;

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
        let mut pool_directory = CompressedLightAccount::<PoolDirectory>::new_init(
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

    pub fn provision_next_pool<'info>(
        ctx: Context<'_, '_, '_, 'info, ProvisionNextPool<'info>>,
        params: ProvisionNextPoolParams,
    ) -> Result<()> {
        // Rollover waits for all 256 vault indexes, so prepaid Squads capacity is never stranded.
        validate_current_pool_directory(
            &params.current_directory,
            &params.directory_account_meta,
            params.expected_active_pool_index,
        )?;

        validate_exhausted_pool_allocator(
            &ctx.accounts.current_pool_allocator,
            params.current_directory.active_pool_index,
        )?;

        let next_pool_index = params
            .current_directory
            .active_pool_index
            .checked_add(1)
            .ok_or_else(|| error!(PasskeyRegistryError::PoolIndexOverflow))?;
        let (expected_next_settings, _) = derive_squads_settings(next_pool_index);
        if ctx.accounts.new_squads_settings.key() != expected_next_settings
            || params.new_squads_settings != expected_next_settings
        {
            return err!(PasskeyRegistryError::InvalidSquadsSettings);
        }

        let (verifier, _) = derive_verifier_pda();
        prefund_squads_settings_for_create(
            &ctx.accounts.current_pool_allocator.to_account_info(),
            &ctx.accounts.new_squads_settings.to_account_info(),
            ctx.accounts.program_config.as_ref(),
        )?;
        invoke_squads_create_smart_account(
            &ctx.accounts.program_config,
            &ctx.accounts.treasury,
            &ctx.accounts.current_pool_allocator,
            &ctx.accounts.system_program,
            &ctx.accounts.squads_program,
            &ctx.accounts.new_squads_settings,
            &verifier,
        )?;
        validate_squads_pool_settings(ctx.accounts.new_squads_settings.as_ref(), &verifier)?;

        let new_allocator = &mut ctx.accounts.new_pool_allocator;
        new_allocator.version = POOL_ALLOCATOR_VERSION;
        new_allocator.status = POOL_ALLOCATOR_STATUS_ACTIVE;
        new_allocator.squads_settings = ctx.accounts.new_squads_settings.key();
        new_allocator.next_index = 0;
        new_allocator.bump = ctx.bumps.new_pool_allocator;
        new_allocator.withdraw_authority = ctx.accounts.current_pool_allocator.withdraw_authority;

        transfer_lamports_from_owned_account(
            &ctx.accounts.current_pool_allocator.to_account_info(),
            &ctx.accounts.new_pool_allocator.to_account_info(),
            params.next_allocator_lamports,
        )?;

        let mut pool_directory = CompressedLightAccount::<PoolDirectory>::new_mut(
            &crate::ID,
            &params.directory_account_meta,
            params.current_directory.clone(),
        )?;
        pool_directory.active_pool_index = next_pool_index;

        let light_cpi_accounts = CpiAccounts::new(
            ctx.accounts.fee_payer.as_ref(),
            ctx.remaining_accounts,
            crate::LIGHT_CPI_SIGNER,
        );
        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, params.directory_proof)
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
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
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

        verify_webauthn_secp256r1_instruction(
            ctx.accounts.instructions.as_ref(),
            secp256r1_instruction_index,
            &passkey_pubkey_compressed,
            &execution_challenge,
            &authenticator_data,
            &client_data_json,
        )?;

        let account_index = current_authority.vault_index;
        let mut authority_record = CompressedLightAccount::<PasskeyAuthority>::new_mut(
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

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializePoolAllocatorParams {
    pub create_accounts_proof: CreateAccountsProof,
    pub squads_settings: Pubkey,
    pub withdraw_authority: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ProvisionNextPoolParams {
    pub create_accounts_proof: CreateAccountsProof,
    pub directory_proof: ValidityProof,
    pub directory_account_meta: CompressedAccountMeta,
    pub expected_active_pool_index: u128,
    pub current_directory: PoolDirectory,
    pub new_squads_settings: Pubkey,
    pub next_allocator_lamports: u64,
}

#[derive(Accounts, LightAccounts)]
#[instruction(params: InitializePoolAllocatorParams)]
pub struct InitializePoolAllocator<'info> {
    #[account(mut)]
    pub fee_payer: Signer<'info>,
    /// CHECK: Light validates the compression config PDA for this program.
    pub compression_config: AccountInfo<'info>,
    /// CHECK: Light validates the rent sponsor recorded in the compression config.
    #[account(mut)]
    pub pda_rent_sponsor: AccountInfo<'info>,
    /// CHECK: validated as a static Squads settings account before storing the pool.
    pub squads_settings: UncheckedAccount<'info>,
    #[account(
        init,
        payer = fee_payer,
        space = 8 + PoolAllocator::INIT_SPACE,
        seeds = [POOL_ALLOCATOR_SEED, params.squads_settings.as_ref()],
        bump
    )]
    #[light_account(init)]
    pub pool_allocator: Account<'info, PoolAllocator>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FundPoolAllocator<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,
    #[account(
        mut,
        constraint = pool_allocator.version == POOL_ALLOCATOR_VERSION,
        constraint = pool_allocator.status == POOL_ALLOCATOR_STATUS_ACTIVE
    )]
    pub pool_allocator: Account<'info, PoolAllocator>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawPoolAllocatorSurplus<'info> {
    pub withdraw_authority: Signer<'info>,
    #[account(
        mut,
        constraint = pool_allocator.version == POOL_ALLOCATOR_VERSION,
        constraint = pool_allocator.status == POOL_ALLOCATOR_STATUS_ACTIVE
    )]
    pub pool_allocator: Account<'info, PoolAllocator>,
    /// CHECK: lamport recipient only.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
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

#[derive(Accounts, LightAccounts)]
#[instruction(params: ProvisionNextPoolParams)]
pub struct ProvisionNextPool<'info> {
    #[account(mut)]
    pub fee_payer: Signer<'info>,
    /// CHECK: Light validates the compression config PDA for this program.
    pub compression_config: AccountInfo<'info>,
    /// CHECK: Light validates the rent sponsor recorded in the compression config.
    #[account(mut)]
    pub pda_rent_sponsor: AccountInfo<'info>,
    #[account(
        mut,
        constraint = current_pool_allocator.version == POOL_ALLOCATOR_VERSION,
        constraint = current_pool_allocator.status == POOL_ALLOCATOR_STATUS_ACTIVE
    )]
    pub current_pool_allocator: Account<'info, PoolAllocator>,
    /// CHECK: validated as Squads' global config account by the Squads CPI.
    #[account(mut)]
    pub program_config: UncheckedAccount<'info>,
    /// CHECK: validated against Squads program config by the Squads CPI.
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: validated as the next deterministic Squads settings account.
    #[account(mut)]
    pub new_squads_settings: UncheckedAccount<'info>,
    #[account(
        init,
        payer = fee_payer,
        space = 8 + PoolAllocator::INIT_SPACE,
        seeds = [POOL_ALLOCATOR_SEED, params.new_squads_settings.as_ref()],
        bump
    )]
    #[light_account(init)]
    pub new_pool_allocator: Account<'info, PoolAllocator>,
    /// CHECK: constrained to the Squads smart account program id.
    #[account(address = SQUADS_SMART_ACCOUNT_PROGRAM_ID)]
    pub squads_program: UncheckedAccount<'info>,
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

/// Hot Light-PDA state for the next vault index and rollover float in one Squads pool.
#[account]
#[derive(Debug, Default, InitSpace, light_account::LightAccount)]
pub struct PoolAllocator {
    pub compression_info: CompressionInfo,
    pub version: u8,
    pub status: u8,
    pub squads_settings: Pubkey,
    pub next_index: u16,
    pub bump: u8,
    pub withdraw_authority: Pubkey,
}

impl PoolAllocator {
    pub const SPACE: usize = 8 + Self::INIT_SPACE;

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

fn transfer_lamports_from_owned_account(
    source: &AccountInfo<'_>,
    destination: &AccountInfo<'_>,
    lamports: u64,
) -> Result<()> {
    let source_lamports = source.lamports();
    if source_lamports < lamports {
        return err!(PasskeyRegistryError::InsufficientPoolAllocatorLamports);
    }

    **source.try_borrow_mut_lamports()? = source_lamports
        .checked_sub(lamports)
        .ok_or_else(|| error!(PasskeyRegistryError::InsufficientPoolAllocatorLamports))?;
    **destination.try_borrow_mut_lamports()? = destination
        .lamports()
        .checked_add(lamports)
        .ok_or_else(|| error!(PasskeyRegistryError::InsufficientPoolAllocatorLamports))?;

    Ok(())
}

fn prefund_squads_settings_for_create(
    pool_allocator: &AccountInfo<'_>,
    new_squads_settings: &AccountInfo<'_>,
    program_config: &AccountInfo<'_>,
) -> Result<()> {
    let config_data = program_config
        .try_borrow_data()
        .map_err(|_| error!(PasskeyRegistryError::InvalidSquadsProgramConfig))?;
    if config_data.len() < 8 {
        return err!(PasskeyRegistryError::InvalidSquadsProgramConfig);
    }
    let mut config_data = &config_data[8..];
    let config = SquadsProgramConfigView::deserialize(&mut config_data)
        .map_err(|_| error!(PasskeyRegistryError::InvalidSquadsProgramConfig))?;
    if config.smart_account_creation_fee != 0 {
        return err!(PasskeyRegistryError::UnsupportedSquadsCreationFee);
    }

    let required_lamports = Rent::get()?.minimum_balance(SQUADS_ONE_SIGNER_SETTINGS_SPACE);
    let top_up = required_lamports.saturating_sub(new_squads_settings.lamports());
    if top_up > 0 {
        transfer_lamports_from_owned_account(pool_allocator, new_squads_settings, top_up)?;
    }

    Ok(())
}

fn invoke_squads_create_smart_account<'info>(
    program_config: &UncheckedAccount<'info>,
    treasury: &UncheckedAccount<'info>,
    creator: &Account<'info, PoolAllocator>,
    system_program: &Program<'info, System>,
    squads_program: &UncheckedAccount<'info>,
    settings: &UncheckedAccount<'info>,
    verifier: &Pubkey,
) -> Result<()> {
    let args = SquadsCreateSmartAccountArgs {
        settings_authority: None,
        threshold: 1,
        signers: vec![SquadsSmartAccountSignerArgs {
            key: *verifier,
            permissions: SquadsPermissionsView {
                mask: SQUADS_FULL_PERMISSIONS_MASK,
            },
        }],
        time_lock: 0,
        rent_collector: None,
        memo: None,
    };
    let mut data = Vec::from(SQUADS_CREATE_SMART_ACCOUNT_DISCRIMINATOR);
    args.serialize(&mut data)
        .map_err(|_| error!(PasskeyRegistryError::InvalidSquadsCreatePayload))?;

    let instruction = Instruction {
        program_id: squads_program.key(),
        accounts: vec![
            AccountMeta::new(program_config.key(), false),
            AccountMeta::new(treasury.key(), false),
            AccountMeta::new(creator.key(), true),
            AccountMeta::new_readonly(system_program.key(), false),
            AccountMeta::new_readonly(squads_program.key(), false),
            AccountMeta::new(settings.key(), false),
        ],
        data,
    };
    let account_infos = [
        program_config.to_account_info(),
        treasury.to_account_info(),
        creator.to_account_info(),
        system_program.to_account_info(),
        squads_program.to_account_info(),
        settings.to_account_info(),
    ];
    let allocator_bump = [creator.bump];
    let signer_seeds: &[&[u8]] = &[
        POOL_ALLOCATOR_SEED,
        creator.squads_settings.as_ref(),
        &allocator_bump,
    ];
    invoke_signed(&instruction, &account_infos, &[signer_seeds])?;

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

fn verify_webauthn_secp256r1_instruction(
    instructions: &AccountInfo<'_>,
    instruction_index: u8,
    expected_pubkey: &[u8; 33],
    expected_challenge: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
) -> Result<()> {
    validate_webauthn_authenticator_data(authenticator_data)?;
    validate_webauthn_client_data_json(client_data_json, expected_challenge)?;

    let client_data_hash = hashv(&[client_data_json]).to_bytes();
    let mut signed_message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    signed_message.extend_from_slice(authenticator_data);
    signed_message.extend_from_slice(&client_data_hash);

    verify_secp256r1_instruction(
        instructions,
        instruction_index,
        expected_pubkey,
        &signed_message,
    )
}

fn validate_webauthn_authenticator_data(authenticator_data: &[u8]) -> Result<()> {
    if authenticator_data.len() < 33
        || authenticator_data.len() > WEBAUTHN_MAX_AUTHENTICATOR_DATA_LEN
    {
        return err!(PasskeyRegistryError::InvalidWebAuthnAuthenticatorData);
    }

    let flags = authenticator_data[32];
    let user_present = flags & 0x01 != 0;
    let user_verified = flags & 0x04 != 0;
    if !user_present || !user_verified {
        return err!(PasskeyRegistryError::InvalidWebAuthnAuthenticatorData);
    }

    Ok(())
}

fn validate_webauthn_client_data_json(
    client_data_json: &[u8],
    expected_challenge: &[u8],
) -> Result<()> {
    if client_data_json.is_empty() || client_data_json.len() > WEBAUTHN_MAX_CLIENT_DATA_JSON_LEN {
        return err!(PasskeyRegistryError::InvalidWebAuthnClientDataJson);
    }

    let expected_challenge_base64url = base64url_encode(expected_challenge);
    let challenge = json_string_field(client_data_json, b"challenge")?;
    let credential_type = json_string_field(client_data_json, b"type")?;

    if challenge != expected_challenge_base64url.as_bytes() || credential_type != WEBAUTHN_GET_TYPE
    {
        return err!(PasskeyRegistryError::InvalidWebAuthnClientDataJson);
    }

    Ok(())
}

fn json_string_field<'a>(json: &'a [u8], field: &[u8]) -> Result<&'a [u8]> {
    let mut key = Vec::with_capacity(field.len() + 2);
    key.push(b'"');
    key.extend_from_slice(field);
    key.push(b'"');

    let key_start = json
        .windows(key.len())
        .position(|window| window == key.as_slice())
        .ok_or_else(|| error!(PasskeyRegistryError::InvalidWebAuthnClientDataJson))?;
    let mut cursor = key_start + key.len();

    while cursor < json.len() && json[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if cursor >= json.len() || json[cursor] != b':' {
        return err!(PasskeyRegistryError::InvalidWebAuthnClientDataJson);
    }
    cursor += 1;

    while cursor < json.len() && json[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if cursor >= json.len() || json[cursor] != b'"' {
        return err!(PasskeyRegistryError::InvalidWebAuthnClientDataJson);
    }
    cursor += 1;
    let value_start = cursor;

    while cursor < json.len() {
        match json[cursor] {
            b'"' => return Ok(&json[value_start..cursor]),
            b'\\' => return err!(PasskeyRegistryError::InvalidWebAuthnClientDataJson),
            _ => cursor += 1,
        }
    }

    err!(PasskeyRegistryError::InvalidWebAuthnClientDataJson)
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

#[derive(AnchorSerialize, Clone, Debug)]
pub struct SquadsCreateSmartAccountArgs {
    pub settings_authority: Option<Pubkey>,
    pub threshold: u16,
    pub signers: Vec<SquadsSmartAccountSignerArgs>,
    pub time_lock: u32,
    pub rent_collector: Option<Pubkey>,
    pub memo: Option<String>,
}

#[derive(AnchorSerialize, Clone, Debug)]
pub struct SquadsSmartAccountSignerArgs {
    pub key: Pubkey,
    pub permissions: SquadsPermissionsView,
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
struct SquadsProgramConfigView {
    _smart_account_index: u128,
    _authority: Pubkey,
    smart_account_creation_fee: u64,
    _treasury: Pubkey,
    _reserved: [u8; 64],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SquadsPermissionsView {
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
    #[msg("The Squads smart account creation payload could not be serialized")]
    InvalidSquadsCreatePayload,
    #[msg("The Squads program config account could not be read")]
    InvalidSquadsProgramConfig,
    #[msg("The pooled Squads creation path requires a zero Squads creation fee")]
    UnsupportedSquadsCreationFee,
    #[msg("The signer is not allowed to withdraw allocator surplus")]
    UnauthorizedPoolAllocatorWithdrawal,
    #[msg("The pool allocator does not have enough lamports")]
    InsufficientPoolAllocatorLamports,
    #[msg("The secp256r1 verification instruction must precede the registry instruction")]
    Secp256r1InstructionMustPrecedeRegistry,
    #[msg("Invalid WebAuthn authenticator data")]
    InvalidWebAuthnAuthenticatorData,
    #[msg("Invalid WebAuthn client data JSON")]
    InvalidWebAuthnClientDataJson,
}
