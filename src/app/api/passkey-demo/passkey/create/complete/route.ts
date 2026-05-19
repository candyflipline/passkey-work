import {
  bytesFromBase64Url,
  bytesToBase64Url,
} from "@/features/passkey-integration-demo/server/encoding";
import {
  assertWebAuthnChallenge,
  jsonError,
  readJson,
} from "@/features/passkey-integration-demo/server/http";
import {
  getDemoStore,
  p256KeyId,
  takePendingRegistration,
} from "@/features/passkey-integration-demo/server/demo-store";
import { buildBackendSponsoredEnvelope } from "@/features/passkey-integration-demo/server/demo-transactions";
import type {
  CompletePasskeyRegistrationRequest,
  CompletePasskeyRegistrationResponse,
} from "@/features/passkey-integration-demo/types";

export async function POST(request: Request) {
  try {
    const input = await readJson<CompletePasskeyRegistrationRequest>(request);
    const pending = takePendingRegistration(input.registrationId);

    if (!pending) {
      throw new Error("Registration challenge was not found or has already been used.");
    }

    assertWebAuthnChallenge({
      clientDataJson: bytesFromBase64Url(input.assertion.clientDataJson),
      expectedChallenge: bytesToBase64Url(pending.registrationChallenge),
    });

    const transaction = await buildBackendSponsoredEnvelope({
      authority: pending.ed25519Authority,
      passkeyPublicKey: pending.passkeyPublicKey,
      assertion: input.assertion,
    });
    const store = getDemoStore();

    store.passkeysByP256.set(p256KeyId(pending.passkeyPublicKey), pending.account);

    return Response.json({
      account: pending.account,
      transaction,
    } satisfies CompletePasskeyRegistrationResponse);
  } catch (error) {
    return jsonError(error);
  }
}
