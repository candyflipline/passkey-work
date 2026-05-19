import { createPasskeySecp256r1Instruction, type CompressedP256PublicKey } from "@loyal/passkey-sdk";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { createHash } from "node:crypto";
import { bytesFromBase64Url } from "./encoding";
import type { DemoTransactionEnvelope, SerializedPasskeyAssertion } from "../types";

const DEMO_BLOCKHASH = "11111111111111111111111111111111";

export function getBackendSponsor() {
  const seedMaterial =
    process.env.PASSKEY_DEMO_SPONSOR_SEED ?? "loyal-passkey-demo-backend-sponsor";
  const seed = createHash("sha256").update(seedMaterial).digest().subarray(0, 32);

  return Keypair.fromSeed(seed);
}

export async function buildBackendSponsoredEnvelope({
  authority,
  passkeyPublicKey,
  assertion,
}: {
  authority: PublicKey;
  passkeyPublicKey: CompressedP256PublicKey;
  assertion: SerializedPasskeyAssertion;
}) {
  return buildSponsoredEnvelope({
    authority,
    instructions: [
      await createPasskeySecp256r1Instruction({
        passkeyPublicKey,
        assertion: {
          authenticatorData: bytesFromBase64Url(assertion.authenticatorData),
          clientDataJson: bytesFromBase64Url(assertion.clientDataJson),
          signature: bytesFromBase64Url(assertion.signature),
        },
      }),
      authoritySignatureMarker(authority),
    ],
    note:
      "Backend-sponsored passkey account-init envelope: backend fee payer signature is attached; the PRF authority still signs the transaction client-side before submission.",
  });
}

export function buildBackendSponsoredWalletEnvelope(authority: PublicKey) {
  return buildSponsoredEnvelope({
    authority,
    instructions: [authoritySignatureMarker(authority)],
    note:
      "Backend-sponsored wallet account-init envelope: backend fee payer signature is attached; the connected wallet still signs as authority before submission.",
  });
}

function buildSponsoredEnvelope({
  authority,
  instructions,
  note,
}: {
  authority: PublicKey;
  instructions: TransactionInstruction[];
  note: string;
}) {
  const sponsor = getBackendSponsor();
  const transaction = new Transaction({
    feePayer: sponsor.publicKey,
    recentBlockhash: DEMO_BLOCKHASH,
  });

  transaction.add(...instructions);
  transaction.partialSign(sponsor);

  return {
    mode: "backend-sponsored",
    feePayer: sponsor.publicKey.toBase58(),
    requiredSigners: [sponsor.publicKey.toBase58(), authority.toBase58()],
    attachedSigners: [sponsor.publicKey.toBase58()],
    transactionBase64: transaction.serialize({ requireAllSignatures: false }).toString("base64"),
    submissionStatus: "not-submitted",
    note,
  } satisfies DemoTransactionEnvelope;
}

function authoritySignatureMarker(authority: PublicKey) {
  return SystemProgram.transfer({
    fromPubkey: authority,
    toPubkey: authority,
    lamports: 0,
  });
}
