import { bytesToBase64Url, randomBytes } from "@/features/passkey-integration-demo/server/encoding";
import type { CreatePasskeyBeginResponse } from "@/features/passkey-integration-demo/types";

export async function POST() {
  return Response.json({
    relyingPartyName: "Loyal",
    userName: `demo-${Date.now()}`,
    displayName: "Loyal demo user",
    creationChallenge: bytesToBase64Url(randomBytes(32)),
  } satisfies CreatePasskeyBeginResponse);
}
