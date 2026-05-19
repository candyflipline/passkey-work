import { deriveAddress, deriveAddressSeed } from "@lightprotocol/stateless.js/browser";
import { PublicKey } from "@solana/web3.js";
import {
  LIGHT_ADDRESS_TREE_V2,
  PASSKEY_AUTHORITY_DATA_LENGTH,
  PASSKEY_AUTHORITY_SEED,
  PASSKEY_REGISTRY_PROGRAM_ID,
  POOL_ALLOCATOR_SEED,
  POOL_DIRECTORY_SEED,
  SQUADS_SEED_PREFIX,
  SQUADS_SEED_SETTINGS,
  SQUADS_SEED_SMART_ACCOUNT,
  SQUADS_SMART_ACCOUNT_PROGRAM_ID,
  VERIFIER_SEED,
  WALLET_AUTHORITY_DOMAIN,
} from "./constants";
import {
  fixedBytes,
  hashv,
  littleEndianU128,
  publicKeyBytes,
  readU64Le,
  utf8,
  type BytesLike,
} from "./bytes";

export type CompressedP256PublicKey = {
  prefix: number;
  x: Uint8Array;
};

export type PasskeyAuthorityRecord = {
  version: number;
  status: number;
  authorityKind: number;
  credentialIdHash: Uint8Array;
  passkeyPublicKey: CompressedP256PublicKey;
  ed25519Authority: PublicKey;
  squadsSettings: PublicKey;
  vaultIndex: number;
  nonce: bigint;
};

export function deriveVerifierPda() {
  return PublicKey.findProgramAddressSync([utf8(VERIFIER_SEED)], PASSKEY_REGISTRY_PROGRAM_ID);
}

export function deriveSquadsSettings(poolIndex: bigint | number) {
  return PublicKey.findProgramAddressSync(
    [utf8(SQUADS_SEED_PREFIX), utf8(SQUADS_SEED_SETTINGS), littleEndianU128(poolIndex)],
    SQUADS_SMART_ACCOUNT_PROGRAM_ID,
  );
}

export function deriveSquadsVault(squadsSettings: PublicKey | string, vaultIndex: number) {
  assertVaultIndex(vaultIndex);

  return PublicKey.findProgramAddressSync(
    [
      utf8(SQUADS_SEED_PREFIX),
      new PublicKey(squadsSettings).toBytes(),
      utf8(SQUADS_SEED_SMART_ACCOUNT),
      new Uint8Array([vaultIndex]),
    ],
    SQUADS_SMART_ACCOUNT_PROGRAM_ID,
  );
}

export function derivePoolAllocator(squadsSettings: PublicKey | string) {
  return PublicKey.findProgramAddressSync(
    [utf8(POOL_ALLOCATOR_SEED), new PublicKey(squadsSettings).toBytes()],
    PASSKEY_REGISTRY_PROGRAM_ID,
  );
}

export function derivePasskeyAuthorityAddress(
  credentialIdHash: BytesLike,
  addressTree: PublicKey | string = LIGHT_ADDRESS_TREE_V2,
) {
  const seed = deriveAddressSeed(
    [utf8(PASSKEY_AUTHORITY_SEED), fixedBytes(credentialIdHash, 32, "credentialIdHash")],
    PASSKEY_REGISTRY_PROGRAM_ID,
  );

  return deriveAddress(seed, new PublicKey(addressTree), PASSKEY_REGISTRY_PROGRAM_ID);
}

export function deriveWalletAuthorityAddress(
  walletAuthorityHash: BytesLike,
  addressTree: PublicKey | string = LIGHT_ADDRESS_TREE_V2,
) {
  const seed = deriveAddressSeed(
    [
      utf8(PASSKEY_AUTHORITY_SEED),
      utf8(WALLET_AUTHORITY_DOMAIN),
      fixedBytes(walletAuthorityHash, 32, "walletAuthorityHash"),
    ],
    PASSKEY_REGISTRY_PROGRAM_ID,
  );

  return deriveAddress(seed, new PublicKey(addressTree), PASSKEY_REGISTRY_PROGRAM_ID);
}

export async function walletAuthorityHash(authority: PublicKey | string) {
  return hashv([utf8(WALLET_AUTHORITY_DOMAIN), publicKeyBytes(authority)]);
}

export function derivePoolDirectoryAddress(addressTree: PublicKey | string = LIGHT_ADDRESS_TREE_V2) {
  const seed = deriveAddressSeed([utf8(POOL_DIRECTORY_SEED)], PASSKEY_REGISTRY_PROGRAM_ID);

  return deriveAddress(seed, new PublicKey(addressTree), PASSKEY_REGISTRY_PROGRAM_ID);
}

export function decodePasskeyAuthorityRecord(data: BytesLike): PasskeyAuthorityRecord {
  const input = fixedBytes(data, PASSKEY_AUTHORITY_DATA_LENGTH, "PasskeyAuthority data");
  let offset = 0;
  const version = input[offset];

  offset += 1;
  const status = input[offset];

  offset += 1;
  const authorityKind = input[offset];

  offset += 1;
  const credentialIdHash = input.slice(offset, offset + 32);

  offset += 32;
  const prefix = input[offset];

  offset += 1;
  const x = input.slice(offset, offset + 32);

  offset += 32;
  const ed25519Authority = new PublicKey(input.slice(offset, offset + 32));

  offset += 32;
  const squadsSettings = new PublicKey(input.slice(offset, offset + 32));

  offset += 32;
  const vaultIndex = input[offset];

  offset += 1;
  const nonce = readU64Le(input, offset);

  return {
    version,
    status,
    authorityKind,
    credentialIdHash,
    passkeyPublicKey: { prefix, x },
    ed25519Authority,
    squadsSettings,
    vaultIndex,
    nonce,
  };
}

export function deriveSmartAccountAddressesForAuthority(authority: PasskeyAuthorityRecord) {
  const [vault] = deriveSquadsVault(authority.squadsSettings, authority.vaultIndex);

  return {
    squadsSettings: authority.squadsSettings,
    vault,
    vaultIndex: authority.vaultIndex,
  };
}

export function deriveSmartAccountAddressesForPasskeyPublicKey({
  authority,
  passkeyPublicKey,
}: {
  authority: PasskeyAuthorityRecord;
  passkeyPublicKey: CompressedP256PublicKey;
}) {
  assertCompressedP256PublicKeyMatches(authority, passkeyPublicKey);

  return deriveSmartAccountAddressesForAuthority(authority);
}

export function assertCompressedP256PublicKeyMatches(
  authority: PasskeyAuthorityRecord,
  passkeyPublicKey: CompressedP256PublicKey,
) {
  if (
    authority.passkeyPublicKey.prefix !== passkeyPublicKey.prefix ||
    !bytesEqual(authority.passkeyPublicKey.x, passkeyPublicKey.x)
  ) {
    throw new Error("The passkey public key does not match the authority record.");
  }
}

function assertVaultIndex(value: number) {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error("vaultIndex must be an integer from 0 through 255.");
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array) {
  if (left.length !== right.length) {
    return false;
  }

  return left.every((value, index) => value === right[index]);
}
