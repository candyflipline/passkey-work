import type {
  CompletePasskeyRegistrationRequest,
  CompletePasskeyRegistrationResponse,
  CreatePasskeyBeginResponse,
  LoginPasskeyBeginResponse,
  LoginPasskeyCompleteRequest,
  LoginPasskeyCompleteResponse,
  PreparePasskeyRegistrationRequest,
  PreparePasskeyRegistrationResponse,
  WalletLoginRequest,
  WalletLoginResponse,
} from "../types";

export function beginPasskeyCreate() {
  return postJson<CreatePasskeyBeginResponse>("/api/passkey-demo/passkey/create/begin");
}

export function preparePasskeyRegistration(input: PreparePasskeyRegistrationRequest) {
  return postJson<PreparePasskeyRegistrationResponse>(
    "/api/passkey-demo/passkey/create/prepare",
    input,
  );
}

export function completePasskeyRegistration(input: CompletePasskeyRegistrationRequest) {
  return postJson<CompletePasskeyRegistrationResponse>(
    "/api/passkey-demo/passkey/create/complete",
    input,
  );
}

export function beginPasskeyLogin() {
  return postJson<LoginPasskeyBeginResponse>("/api/passkey-demo/passkey/login/begin");
}

export function completePasskeyLogin(input: LoginPasskeyCompleteRequest) {
  return postJson<LoginPasskeyCompleteResponse>("/api/passkey-demo/passkey/login/complete", input);
}

export function loginWallet(input: WalletLoginRequest) {
  return postJson<WalletLoginResponse>("/api/passkey-demo/wallet/login", input);
}

async function postJson<TResponse>(path: string, body?: unknown) {
  const response = await fetch(path, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = (await response.json()) as TResponse | { error?: string };

  if (!response.ok) {
    const message =
      typeof payload === "object" && payload !== null && "error" in payload && payload.error
        ? payload.error
        : "Demo API request failed.";

    throw new Error(message);
  }

  return payload as TResponse;
}
