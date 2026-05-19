import { createRegistrationId, savePasskeyLoginChallenge } from "@/features/passkey-integration-demo/server/demo-store";
import { bytesToBase64Url, randomBytes } from "@/features/passkey-integration-demo/server/encoding";
import type { LoginPasskeyBeginResponse } from "@/features/passkey-integration-demo/types";

export async function POST() {
  const loginId = createRegistrationId();
  const challenge = randomBytes(32);

  savePasskeyLoginChallenge(loginId, challenge);

  return Response.json({
    loginId,
    loginChallenge: bytesToBase64Url(challenge),
  } satisfies LoginPasskeyBeginResponse);
}
