import {
  getDemoStore,
  p256KeyId,
  takePasskeyLoginChallenge,
} from "@/features/passkey-integration-demo/server/demo-store";
import {
  bytesFromBase64Url,
  bytesToBase64Url,
} from "@/features/passkey-integration-demo/server/encoding";
import {
  assertWebAuthnChallenge,
  jsonError,
  readJson,
} from "@/features/passkey-integration-demo/server/http";
import type {
  LoginPasskeyCompleteRequest,
  LoginPasskeyCompleteResponse,
} from "@/features/passkey-integration-demo/types";

export async function POST(request: Request) {
  try {
    const input = await readJson<LoginPasskeyCompleteRequest>(request);
    const challenge = takePasskeyLoginChallenge(input.loginId);

    if (!challenge) {
      throw new Error("Login challenge was not found or has already been used.");
    }

    assertWebAuthnChallenge({
      clientDataJson: bytesFromBase64Url(input.assertion.clientDataJson),
      expectedChallenge: bytesToBase64Url(challenge),
    });

    const account = getDemoStore().passkeysByP256.get(p256KeyId(input.passkeyPublicKey)) ?? null;

    return Response.json({
      account,
      matchedBy: "p256-public-key",
    } satisfies LoginPasskeyCompleteResponse);
  } catch (error) {
    return jsonError(error);
  }
}
