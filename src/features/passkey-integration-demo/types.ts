export type HexByteString = string;

export type SerializedP256PublicKey = {
  prefix: number;
  x: HexByteString;
};

export type DemoAccount = {
  accountId: string;
  kind: "passkey" | "wallet";
  authority: string;
  authorityAddress: string;
  createdAt: string;
  vaultIndex: number;
  squadsSettings: string;
  vault: string;
};

export type DemoTransactionEnvelope = {
  mode: "backend-sponsored";
  feePayer: string;
  requiredSigners: string[];
  attachedSigners: string[];
  transactionBase64: string;
  submissionStatus: "not-submitted";
  note: string;
};

export type CreatePasskeyBeginResponse = {
  relyingPartyName: string;
  userName: string;
  displayName: string;
  creationChallenge: string;
};

export type PreparePasskeyRegistrationRequest = {
  credentialIdHash: string;
  passkeyPublicKey: SerializedP256PublicKey;
  ed25519Authority: string;
};

export type PreparePasskeyRegistrationResponse = {
  registrationId: string;
  registrationChallenge: string;
  account: DemoAccount;
};

export type CompletePasskeyRegistrationRequest = {
  registrationId: string;
  assertion: SerializedPasskeyAssertion;
};

export type CompletePasskeyRegistrationResponse = {
  account: DemoAccount;
  transaction: DemoTransactionEnvelope;
};

export type LoginPasskeyBeginResponse = {
  loginId: string;
  loginChallenge: string;
};

export type LoginPasskeyCompleteRequest = {
  loginId: string;
  credentialIdHash: string;
  passkeyPublicKey: SerializedP256PublicKey;
  assertion: SerializedPasskeyAssertion;
};

export type LoginPasskeyCompleteResponse = {
  account: DemoAccount | null;
  matchedBy: "p256-public-key";
};

export type WalletLoginRequest = {
  walletAddress: string;
};

export type WalletLoginResponse = {
  account: DemoAccount | null;
  status: "found" | "needs-create";
  transaction: DemoTransactionEnvelope | null;
};

export type SerializedPasskeyAssertion = {
  credentialId: string;
  authenticatorData: string;
  clientDataJson: string;
  signature: string;
};
