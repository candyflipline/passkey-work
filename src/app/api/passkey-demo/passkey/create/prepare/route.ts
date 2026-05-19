import { buildRegistrationChallenge, LIGHT_ADDRESS_TREE_V2 } from "@loyal/passkey-sdk";
import { PublicKey } from "@solana/web3.js";
import {
  createPasskeyAccount,
  createRegistrationId,
  savePendingRegistration,
  serializeP256PublicKey,
} from "@/features/passkey-integration-demo/server/demo-store";
import {
  bytesFromBase64Url,
  bytesToBase64Url,
} from "@/features/passkey-integration-demo/server/encoding";
import { jsonError, readJson } from "@/features/passkey-integration-demo/server/http";
import type {
  PreparePasskeyRegistrationRequest,
  PreparePasskeyRegistrationResponse,
} from "@/features/passkey-integration-demo/types";

export async function POST(request: Request) {
  try {
    const input = await readJson<PreparePasskeyRegistrationRequest>(request);
    const credentialIdHash = bytesFromBase64Url(input.credentialIdHash);
    const passkeyPublicKey = serializeP256PublicKey(input.passkeyPublicKey);
    const ed25519Authority = new PublicKey(input.ed25519Authority);
    const account = createPasskeyAccount({
      credentialIdHash,
      passkeyPublicKey,
      ed25519Authority,
    });
    const registrationId = createRegistrationId();
    const registrationChallenge = buildRegistrationChallenge({
      credentialIdHash,
      passkeyPublicKey,
      ed25519Authority,
      addressTree: LIGHT_ADDRESS_TREE_V2,
      squadsSettings: account.squadsSettings,
      vaultIndex: account.vaultIndex,
    });

    savePendingRegistration({
      id: registrationId,
      account,
      credentialIdHash,
      passkeyPublicKey,
      ed25519Authority,
      registrationChallenge,
    });

    return Response.json({
      registrationId,
      registrationChallenge: bytesToBase64Url(registrationChallenge),
      account,
    } satisfies PreparePasskeyRegistrationResponse);
  } catch (error) {
    return jsonError(error);
  }
}
