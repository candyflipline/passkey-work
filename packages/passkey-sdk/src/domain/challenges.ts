import { AccountMeta, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  EXECUTION_DOMAIN,
  PASSKEY_REGISTRY_PROGRAM_ID,
  REGISTRATION_DOMAIN,
  SQUADS_SMART_ACCOUNT_PROGRAM_ID,
} from "./constants.js";
import {
  concatBytes,
  fixedBytes,
  hashv,
  littleEndianI64,
  littleEndianU64,
  publicKeyBytes,
  utf8,
  type BytesLike,
} from "./bytes.js";
import { deriveVerifierPda } from "./addresses.js";

export function compressedP256PublicKeyBytes({
  prefix,
  x,
}: {
  prefix: number;
  x: BytesLike;
}) {
  if (prefix !== 2 && prefix !== 3) {
    throw new Error("P-256 public key prefix must be 2 or 3.");
  }

  return concatBytes([new Uint8Array([prefix]), fixedBytes(x, 32, "passkeyPublicKey.x")]);
}

export function buildRegistrationChallenge({
  credentialIdHash,
  passkeyPublicKey,
  ed25519Authority,
  addressTree,
  squadsSettings,
  vaultIndex,
}: {
  credentialIdHash: BytesLike;
  passkeyPublicKey: { prefix: number; x: BytesLike };
  ed25519Authority: PublicKey | string;
  addressTree: PublicKey | string;
  squadsSettings: PublicKey | string;
  vaultIndex: number;
}) {
  return concatBytes([
    utf8(REGISTRATION_DOMAIN),
    PASSKEY_REGISTRY_PROGRAM_ID.toBytes(),
    publicKeyBytes(ed25519Authority),
    fixedBytes(credentialIdHash, 32, "credentialIdHash"),
    new Uint8Array([passkeyPublicKey.prefix]),
    fixedBytes(passkeyPublicKey.x, 32, "passkeyPublicKey.x"),
    publicKeyBytes(addressTree),
    publicKeyBytes(squadsSettings),
    new Uint8Array([vaultIndex]),
    littleEndianU64(0),
  ]);
}

export async function buildExecutionChallenge({
  credentialIdHash,
  passkeyPublicKey,
  ed25519Authority,
  squadsSettings,
  vaultIndex,
  nonce,
  expiresAtUnixTimestamp,
  squadsPayload,
  squadsAccounts,
}: {
  credentialIdHash: BytesLike;
  passkeyPublicKey: { prefix: number; x: BytesLike };
  ed25519Authority: PublicKey | string;
  squadsSettings: PublicKey | string;
  vaultIndex: number;
  nonce: bigint | number;
  expiresAtUnixTimestamp: bigint | number;
  squadsPayload: BytesLike;
  squadsAccounts: AccountMeta[];
}) {
  const [verifier] = deriveVerifierPda();

  return concatBytes([
    utf8(EXECUTION_DOMAIN),
    PASSKEY_REGISTRY_PROGRAM_ID.toBytes(),
    SQUADS_SMART_ACCOUNT_PROGRAM_ID.toBytes(),
    verifier.toBytes(),
    publicKeyBytes(ed25519Authority),
    fixedBytes(credentialIdHash, 32, "credentialIdHash"),
    new Uint8Array([passkeyPublicKey.prefix]),
    fixedBytes(passkeyPublicKey.x, 32, "passkeyPublicKey.x"),
    publicKeyBytes(squadsSettings),
    new Uint8Array([vaultIndex]),
    littleEndianU64(nonce),
    littleEndianI64(expiresAtUnixTimestamp),
    await hashv([squadsPayload]),
    await hashSquadsAccountMetas(squadsAccounts),
  ]);
}

export async function hashSquadsAccountMetas(accounts: AccountMeta[]) {
  return hashv([
    concatBytes(
      accounts.map((account) =>
        concatBytes([
          account.pubkey.toBytes(),
          new Uint8Array([account.isWritable ? 1 : 0, account.isSigner ? 1 : 0]),
        ]),
      ),
    ),
  ]);
}

export function createSquadsSystemTransferPayload(lamports: bigint | number) {
  const transferData = SystemProgram.transfer({
    fromPubkey: PublicKey.default,
    toPubkey: PublicKey.default,
    lamports: Number(lamports),
  }).data;
  const payload = new Uint8Array(7 + transferData.length);
  const view = new DataView(payload.buffer);

  payload[0] = 1;
  payload[1] = 2;
  payload[2] = 2;
  payload[3] = 0;
  payload[4] = 1;
  view.setUint16(5, transferData.length, true);
  payload.set(transferData, 7);

  return payload;
}
