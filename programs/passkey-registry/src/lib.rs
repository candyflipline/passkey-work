#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked;
use light_sdk::{
    account::LightAccount,
    address::v2::derive_address,
    cpi::{v2::CpiAccounts, CpiSigner},
    derive_light_cpi_signer,
    instruction::{PackedAddressTreeInfo, ValidityProof},
    LightDiscriminator, PackedAddressTreeInfoExt,
};
use light_sdk_types::ADDRESS_TREE_V2;

declare_id!("rTvZY3rX9PBXyWzHtMRnY92o7EiEFSwsYZKoCLxUY9X");

pub const PASSKEY_AUTHORITY_VERSION: u8 = 1;
pub const PASSKEY_AUTHORITY_STATUS_ACTIVE: u8 = 1;
pub const PASSKEY_AUTHORITY_SEED: &[u8] = b"passkey-authority";
pub const REGISTRATION_DOMAIN: &[u8] = b"LOYAL_PASSKEY_REGISTER_V1";
pub const SECP256R1_PROGRAM_ID: Pubkey = pubkey!("Secp256r1SigVerify1111111111111111111111111");

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

        let registration_challenge = build_registration_challenge(
            &credential_id_hash,
            passkey_pubkey_prefix,
            &passkey_pubkey_x,
            &ctx.accounts.authority.key(),
            &address_tree_pubkey,
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
        authority_record.nonce = 0;

        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, proof)
            .with_light_account(authority_record)?
            .with_new_addresses(&[
                address_tree_info.into_new_address_params_assigned_packed(address_seed, Some(0))
            ])
            .invoke(light_cpi_accounts)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreatePasskeyAuthority<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: constrained to the instructions sysvar address.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
}

#[event]
#[derive(Clone, Debug, Default, LightDiscriminator)]
pub struct PasskeyAuthority {
    pub version: u8,
    pub status: u8,
    pub credential_id_hash: [u8; 32],
    pub passkey_pubkey_prefix: u8,
    pub passkey_pubkey_x: [u8; 32],
    pub ed25519_authority: Pubkey,
    pub nonce: u64,
}

pub fn build_registration_challenge(
    credential_id_hash: &[u8; 32],
    passkey_pubkey_prefix: u8,
    passkey_pubkey_x: &[u8; 32],
    ed25519_authority: &Pubkey,
    address_tree: &Pubkey,
) -> Vec<u8> {
    let mut challenge = Vec::with_capacity(
        REGISTRATION_DOMAIN.len() + 32 + 32 + 32 + 33 + 32 + core::mem::size_of::<u64>(),
    );

    challenge.extend_from_slice(REGISTRATION_DOMAIN);
    challenge.extend_from_slice(crate::ID.as_ref());
    challenge.extend_from_slice(ed25519_authority.as_ref());
    challenge.extend_from_slice(credential_id_hash);
    challenge.push(passkey_pubkey_prefix);
    challenge.extend_from_slice(passkey_pubkey_x);
    challenge.extend_from_slice(address_tree.as_ref());
    challenge.extend_from_slice(&0u64.to_le_bytes());
    challenge
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

fn verify_secp256r1_instruction(
    instructions: &AccountInfo<'_>,
    instruction_index: u8,
    expected_pubkey: &[u8; 33],
    expected_message: &[u8],
) -> Result<()> {
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
}
