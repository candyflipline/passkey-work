import { BorshInstructionCoder, type Idl } from "@coral-xyz/anchor";
import BN from "bn.js";
import {
  AccountMeta,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  PASSKEY_REGISTRY_PROGRAM_ID,
  SECP256R1_PROGRAM_ID,
  SQUADS_SMART_ACCOUNT_PROGRAM_ID,
} from "./constants.js";
import { bytes, concatBytes, fixedBytes, sha256, type BytesLike } from "./bytes.js";
import { compressedP256PublicKeyBytes } from "./challenges.js";
import { deriveVerifierPda } from "./addresses.js";

export type PasskeyAssertionInput = {
  authenticatorData: BytesLike;
  clientDataJson: BytesLike;
  signature: BytesLike;
};

function encodeInstruction(name: string, args: Record<string, unknown>) {
  return new BorshInstructionCoder(passkeyRegistryIdl).encode(name, args);
}

export type CreatePasskeyAuthorityInstructionArgs = {
  authority: PublicKey;
  poolAllocator: PublicKey;
  lightRemainingAccounts: AccountMeta[];
  proof: unknown;
  addressTreeInfo: unknown;
  outputStateTreeIndex: number;
  secp256r1InstructionIndex: number;
  credentialIdHash: BytesLike;
  passkeyPublicKey: {
    prefix: number;
    x: BytesLike;
  };
  assertion: Pick<PasskeyAssertionInput, "authenticatorData" | "clientDataJson">;
};

export type CreateWalletAuthorityInstructionArgs = {
  authority: PublicKey;
  poolAllocator: PublicKey;
  lightRemainingAccounts: AccountMeta[];
  proof: unknown;
  addressTreeInfo: unknown;
  outputStateTreeIndex: number;
};

export type ExecutePasskeyVaultTransactionInstructionArgs = {
  payer: PublicKey;
  squadsSettings: PublicKey;
  lightRemainingAccounts: AccountMeta[];
  squadsInstructionAccounts: AccountMeta[];
  proof: unknown;
  accountMeta: unknown;
  secp256r1InstructionIndex: number;
  expectedNonce: bigint | number;
  expiresAtUnixTimestamp: bigint | number;
  currentAuthority: unknown;
  squadsPayload: BytesLike;
  assertion: Pick<PasskeyAssertionInput, "authenticatorData" | "clientDataJson">;
};

export type ExecuteWalletVaultTransactionInstructionArgs = {
  payer: PublicKey;
  authority: PublicKey;
  squadsSettings: PublicKey;
  lightRemainingAccounts: AccountMeta[];
  squadsInstructionAccounts: AccountMeta[];
  proof: unknown;
  accountMeta: unknown;
  expectedNonce: bigint | number;
  currentAuthority: unknown;
  squadsPayload: BytesLike;
};

export function createSecp256r1Instruction({
  publicKey,
  signature,
  message,
}: {
  publicKey: BytesLike;
  signature: BytesLike;
  message: BytesLike;
}) {
  const publicKeyBytes = fixedBytes(publicKey, 33, "P-256 public key");
  const signatureBytes = fixedBytes(signature, 64, "P-256 signature");
  const messageBytes = bytes(message);
  const headerLength = 16;
  const signatureOffset = headerLength;
  const publicKeyOffset = signatureOffset + signatureBytes.length;
  const messageOffset = publicKeyOffset + publicKeyBytes.length;
  const data = new Uint8Array(messageOffset + messageBytes.length);
  const view = new DataView(data.buffer);

  data[0] = 1;
  view.setUint16(2, signatureOffset, true);
  view.setUint16(4, 0xffff, true);
  view.setUint16(6, publicKeyOffset, true);
  view.setUint16(8, 0xffff, true);
  view.setUint16(10, messageOffset, true);
  view.setUint16(12, messageBytes.length, true);
  view.setUint16(14, 0xffff, true);
  data.set(signatureBytes, signatureOffset);
  data.set(publicKeyBytes, publicKeyOffset);
  data.set(messageBytes, messageOffset);

  return new TransactionInstruction({
    programId: SECP256R1_PROGRAM_ID,
    keys: [],
    data: Buffer.from(data),
  });
}

export async function createPasskeySecp256r1Instruction({
  passkeyPublicKey,
  assertion,
}: {
  passkeyPublicKey: { prefix: number; x: BytesLike };
  assertion: PasskeyAssertionInput;
}) {
  return createSecp256r1Instruction({
    publicKey: compressedP256PublicKeyBytes(passkeyPublicKey),
    signature: assertion.signature,
    message: await webauthnSignedMessage(assertion),
  });
}

async function webauthnSignedMessage({
  authenticatorData,
  clientDataJson,
}: Pick<PasskeyAssertionInput, "authenticatorData" | "clientDataJson">) {
  return concatBytes([bytes(authenticatorData), await sha256(clientDataJson)]);
}

export function createPasskeyAuthorityInstruction(args: CreatePasskeyAuthorityInstructionArgs) {
  return new TransactionInstruction({
    programId: PASSKEY_REGISTRY_PROGRAM_ID,
    keys: [
      { pubkey: args.authority, isSigner: true, isWritable: true },
      { pubkey: args.poolAllocator, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      ...args.lightRemainingAccounts,
    ],
    data: encodeInstruction("create_passkey_authority", {
      proof: args.proof,
      addressTreeInfo: args.addressTreeInfo,
      outputStateTreeIndex: args.outputStateTreeIndex,
      secp256r1InstructionIndex: args.secp256r1InstructionIndex,
      credentialIdHash: Array.from(fixedBytes(args.credentialIdHash, 32, "credentialIdHash")),
      passkeyPubkeyPrefix: args.passkeyPublicKey.prefix,
      passkeyPubkeyX: Array.from(fixedBytes(args.passkeyPublicKey.x, 32, "passkeyPublicKey.x")),
      authenticatorData: Buffer.from(bytes(args.assertion.authenticatorData)),
      clientDataJson: Buffer.from(bytes(args.assertion.clientDataJson)),
    }),
  });
}

export function createWalletAuthorityInstruction(args: CreateWalletAuthorityInstructionArgs) {
  return new TransactionInstruction({
    programId: PASSKEY_REGISTRY_PROGRAM_ID,
    keys: [
      { pubkey: args.authority, isSigner: true, isWritable: true },
      { pubkey: args.poolAllocator, isSigner: false, isWritable: true },
      ...args.lightRemainingAccounts,
    ],
    data: encodeInstruction("create_wallet_authority", {
      proof: args.proof,
      addressTreeInfo: args.addressTreeInfo,
      outputStateTreeIndex: args.outputStateTreeIndex,
    }),
  });
}

export function createExecutePasskeyVaultTransactionInstruction(
  args: ExecutePasskeyVaultTransactionInstructionArgs,
) {
  const [verifier] = deriveVerifierPda();

  return new TransactionInstruction({
    programId: PASSKEY_REGISTRY_PROGRAM_ID,
    keys: [
      { pubkey: args.payer, isSigner: true, isWritable: true },
      { pubkey: args.squadsSettings, isSigner: false, isWritable: true },
      { pubkey: SQUADS_SMART_ACCOUNT_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: verifier, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      ...args.lightRemainingAccounts,
      ...args.squadsInstructionAccounts,
    ],
    data: encodeInstruction("execute_passkey_vault_transaction", {
      proof: args.proof,
      accountMeta: args.accountMeta,
      lightRemainingAccountsCount: args.lightRemainingAccounts.length,
      secp256r1InstructionIndex: args.secp256r1InstructionIndex,
      expectedNonce: new BN(args.expectedNonce.toString()),
      expiresAtUnixTimestamp: new BN(args.expiresAtUnixTimestamp.toString()),
      currentAuthority: args.currentAuthority,
      squadsPayload: Buffer.from(bytes(args.squadsPayload)),
      authenticatorData: Buffer.from(bytes(args.assertion.authenticatorData)),
      clientDataJson: Buffer.from(bytes(args.assertion.clientDataJson)),
    }),
  });
}

export function createExecuteWalletVaultTransactionInstruction(
  args: ExecuteWalletVaultTransactionInstructionArgs,
) {
  const [verifier] = deriveVerifierPda();

  return new TransactionInstruction({
    programId: PASSKEY_REGISTRY_PROGRAM_ID,
    keys: [
      { pubkey: args.payer, isSigner: true, isWritable: true },
      { pubkey: args.authority, isSigner: true, isWritable: false },
      { pubkey: args.squadsSettings, isSigner: false, isWritable: true },
      { pubkey: SQUADS_SMART_ACCOUNT_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: verifier, isSigner: false, isWritable: false },
      ...args.lightRemainingAccounts,
      ...args.squadsInstructionAccounts,
    ],
    data: encodeInstruction("execute_wallet_vault_transaction", {
      proof: args.proof,
      accountMeta: args.accountMeta,
      lightRemainingAccountsCount: args.lightRemainingAccounts.length,
      expectedNonce: new BN(args.expectedNonce.toString()),
      currentAuthority: args.currentAuthority,
      squadsPayload: Buffer.from(bytes(args.squadsPayload)),
    }),
  });
}

export function createInitializePoolAllocatorInstruction({
  feePayer,
  compressionConfig,
  pdaRentSponsor,
  squadsSettings,
  poolAllocator,
  createAccountsProof,
  withdrawAuthority = feePayer,
}: {
  feePayer: PublicKey;
  compressionConfig: PublicKey;
  pdaRentSponsor: PublicKey;
  squadsSettings: PublicKey;
  poolAllocator: PublicKey;
  createAccountsProof: unknown;
  withdrawAuthority?: PublicKey;
}) {
  return new TransactionInstruction({
    programId: PASSKEY_REGISTRY_PROGRAM_ID,
    keys: [
      { pubkey: feePayer, isSigner: true, isWritable: true },
      { pubkey: compressionConfig, isSigner: false, isWritable: false },
      { pubkey: pdaRentSponsor, isSigner: false, isWritable: true },
      { pubkey: squadsSettings, isSigner: false, isWritable: false },
      { pubkey: poolAllocator, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: encodeInstruction("initialize_pool_allocator", {
      params: {
        createAccountsProof,
        squadsSettings,
        withdrawAuthority,
      },
    }),
  });
}

export function createSquadsInstructionAccountsForSystemTransfer({
  vault,
  recipient,
}: {
  vault: PublicKey;
  recipient: PublicKey;
}) {
  return [
    { pubkey: vault, isSigner: false, isWritable: true },
    { pubkey: recipient, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ] satisfies AccountMeta[];
}

const passkeyRegistryIdl = {
  address: PASSKEY_REGISTRY_PROGRAM_ID.toBase58(),
  metadata: {
    name: "passkey_registry",
    version: "0.1.0",
    spec: "0.1.0",
  },
  instructions: [
    {
      name: "create_passkey_authority",
      discriminator: [169, 26, 66, 96, 73, 71, 82, 103],
      accounts: [],
      args: [
        { name: "proof", type: { defined: { name: "ValidityProof" } } },
        { name: "address_tree_info", type: { defined: { name: "PackedAddressTreeInfo" } } },
        { name: "output_state_tree_index", type: "u8" },
        { name: "secp256r1_instruction_index", type: "u8" },
        { name: "credential_id_hash", type: { array: ["u8", 32] } },
        { name: "passkey_pubkey_prefix", type: "u8" },
        { name: "passkey_pubkey_x", type: { array: ["u8", 32] } },
        { name: "authenticator_data", type: "bytes" },
        { name: "client_data_json", type: "bytes" },
      ],
    },
    {
      name: "execute_passkey_vault_transaction",
      discriminator: [236, 187, 4, 119, 38, 154, 11, 65],
      accounts: [],
      args: [
        { name: "proof", type: { defined: { name: "ValidityProof" } } },
        { name: "account_meta", type: { defined: { name: "CompressedAccountMeta" } } },
        { name: "light_remaining_accounts_count", type: "u8" },
        { name: "secp256r1_instruction_index", type: "u8" },
        { name: "expected_nonce", type: "u64" },
        { name: "expires_at_unix_timestamp", type: "i64" },
        { name: "current_authority", type: { defined: { name: "PasskeyAuthority" } } },
        { name: "squads_payload", type: "bytes" },
        { name: "authenticator_data", type: "bytes" },
        { name: "client_data_json", type: "bytes" },
      ],
    },
    {
      name: "create_wallet_authority",
      discriminator: [36, 12, 112, 61, 92, 100, 207, 138],
      accounts: [],
      args: [
        { name: "proof", type: { defined: { name: "ValidityProof" } } },
        { name: "address_tree_info", type: { defined: { name: "PackedAddressTreeInfo" } } },
        { name: "output_state_tree_index", type: "u8" },
      ],
    },
    {
      name: "execute_wallet_vault_transaction",
      discriminator: [218, 116, 215, 244, 122, 65, 220, 163],
      accounts: [],
      args: [
        { name: "proof", type: { defined: { name: "ValidityProof" } } },
        { name: "account_meta", type: { defined: { name: "CompressedAccountMeta" } } },
        { name: "light_remaining_accounts_count", type: "u8" },
        { name: "expected_nonce", type: "u64" },
        { name: "current_authority", type: { defined: { name: "PasskeyAuthority" } } },
        { name: "squads_payload", type: "bytes" },
      ],
    },
    {
      name: "initialize_pool_allocator",
      discriminator: [251, 210, 118, 100, 119, 136, 167, 98],
      accounts: [],
      args: [
        {
          name: "params",
          type: {
            defined: {
              name: "InitializePoolAllocatorParams",
            },
          },
        },
      ],
    },
  ],
  types: [
    {
      name: "CompressedAccountMeta",
      type: {
        kind: "struct",
        fields: [
          { name: "tree_info", type: { defined: { name: "PackedStateTreeInfo" } } },
          { name: "address", type: { array: ["u8", 32] } },
          { name: "output_state_tree_index", type: "u8" },
        ],
      },
    },
    {
      name: "CompressedProof",
      type: {
        kind: "struct",
        fields: [
          { name: "a", type: { array: ["u8", 32] } },
          { name: "b", type: { array: ["u8", 64] } },
          { name: "c", type: { array: ["u8", 32] } },
        ],
      },
    },
    {
      name: "InitializePoolAllocatorParams",
      type: {
        kind: "struct",
        fields: [
          { name: "create_accounts_proof", type: { defined: { name: "CreateAccountsProof" } } },
          { name: "squads_settings", type: "pubkey" },
          { name: "withdraw_authority", type: "pubkey" },
        ],
      },
    },
    {
      name: "CreateAccountsProof",
      type: {
        kind: "struct",
        fields: [
          { name: "proof", type: { defined: { name: "CompressedProof" } } },
          { name: "address_tree_info", type: { defined: { name: "PackedAddressTreeInfo" } } },
          { name: "root_indices", type: { vec: "u16" } },
          { name: "addresses", type: { vec: { array: ["u8", 32] } } },
        ],
      },
    },
    {
      name: "PackedAddressTreeInfo",
      type: {
        kind: "struct",
        fields: [
          { name: "address_merkle_tree_pubkey_index", type: "u8" },
          { name: "address_queue_pubkey_index", type: "u8" },
          { name: "root_index", type: "u16" },
        ],
      },
    },
    {
      name: "PackedStateTreeInfo",
      type: {
        kind: "struct",
        fields: [
          { name: "root_index", type: "u16" },
          { name: "prove_by_index", type: "bool" },
          { name: "merkle_tree_pubkey_index", type: "u8" },
          { name: "queue_pubkey_index", type: "u8" },
          { name: "leaf_index", type: "u32" },
        ],
      },
    },
    {
      name: "PasskeyAuthority",
      type: {
        kind: "struct",
        fields: [
          { name: "version", type: "u8" },
          { name: "status", type: "u8" },
          { name: "authority_kind", type: "u8" },
          { name: "credential_id_hash", type: { array: ["u8", 32] } },
          { name: "passkey_pubkey_prefix", type: "u8" },
          { name: "passkey_pubkey_x", type: { array: ["u8", 32] } },
          { name: "ed25519_authority", type: "pubkey" },
          { name: "squads_settings", type: "pubkey" },
          { name: "vault_index", type: "u8" },
          { name: "nonce", type: "u64" },
        ],
      },
    },
    {
      name: "ValidityProof",
      type: {
        kind: "struct",
        fields: [
          {
            name: "proof",
            type: {
              option: {
                defined: {
                  name: "CompressedProof",
                },
              },
            },
          },
        ],
      },
    },
  ],
} satisfies Idl;
