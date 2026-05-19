export async function readJson<T>(request: Request) {
  try {
    return (await request.json()) as T;
  } catch {
    throw new Error("Expected a JSON request body.");
  }
}

export function jsonError(error: unknown, status = 400) {
  return Response.json(
    { error: error instanceof Error ? error.message : "Unexpected demo API error." },
    { status },
  );
}

export function assertWebAuthnChallenge({
  clientDataJson,
  expectedChallenge,
}: {
  clientDataJson: Uint8Array;
  expectedChallenge: string;
}) {
  const parsed = JSON.parse(new TextDecoder().decode(clientDataJson)) as { challenge?: unknown };

  if (parsed.challenge !== expectedChallenge) {
    throw new Error("Passkey assertion challenge did not match the backend challenge.");
  }
}
