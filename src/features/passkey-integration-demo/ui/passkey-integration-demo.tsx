"use client";

import { useEffect, useState } from "react";
import { useConnect, useWallets, type UiWallet } from "@wallet-standard/react";
import {
  createPasskeyThroughBackend,
  isPasskeySmartAccountSupported,
  loginWithStoredPasskey,
} from "../domain/passkeys";
import {
  listStoredDemoPasskeys,
  type StoredDemoPasskey,
} from "../domain/local-passkeys";
import { loginWithWalletAccount } from "../domain/wallet";
import type { DemoAccount, DemoTransactionEnvelope, WalletLoginResponse } from "../types";

type Status = {
  tone: "idle" | "success" | "error";
  message: string;
};

type DemoResult = {
  account: DemoAccount | null;
  transaction: DemoTransactionEnvelope | null;
};

export function PasskeyIntegrationDemo() {
  const [supportsPasskeys, setSupportsPasskeys] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [status, setStatus] = useState<Status>({
    tone: "idle",
    message: "Ready",
  });
  const [result, setResult] = useState<DemoResult>({
    account: null,
    transaction: null,
  });
  const [storedPasskeys, setStoredPasskeys] = useState<StoredDemoPasskey[]>([]);
  const selectedPasskey = storedPasskeys[0] ?? null;

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setStoredPasskeys(listStoredDemoPasskeys());
      setSupportsPasskeys(isPasskeySmartAccountSupported());
    }, 0);

    return () => window.clearTimeout(timer);
  }, []);

  async function handleCreatePasskey() {
    setPendingAction("create-passkey");
    setStatus({ tone: "idle", message: "Creating passkey" });
    setResult({ account: null, transaction: null });

    try {
      const response = await createPasskeyThroughBackend();

      setStoredPasskeys(listStoredDemoPasskeys());
      setResult({
        account: response.account,
        transaction: response.transaction,
      });
      setStatus({
        tone: "success",
        message: "Backend sponsored registration envelope created",
      });
    } catch (error) {
      setStatus({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setPendingAction(null);
    }
  }

  async function handlePasskeyLogin(passkey: StoredDemoPasskey) {
    setPendingAction("login-passkey");
    setStatus({ tone: "idle", message: "Signing passkey challenge" });
    setResult({ account: null, transaction: null });

    try {
      const response = await loginWithStoredPasskey(passkey);

      setResult({
        account: response.account,
        transaction: null,
      });
      setStatus({
        tone: response.account ? "success" : "error",
        message: response.account ? "Passkey account found" : "No account found for that P-256 key",
      });
    } catch (error) {
      setStatus({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setPendingAction(null);
    }
  }

  function handleWalletResult(response: WalletLoginResponse) {
    setResult({
      account: response.account,
      transaction: response.transaction,
    });
    setStatus({
      tone: "success",
      message:
        response.status === "found"
          ? "Wallet account found"
          : "Wallet account needs sponsored creation",
    });
  }

  return (
    <main className="min-h-screen bg-white text-zinc-950">
      <section className="border-b border-zinc-200">
        <div className="mx-auto flex w-full max-w-6xl flex-col gap-5 px-5 py-8 sm:px-8 lg:py-10">
          <div className="flex flex-col gap-2">
            <p className="text-sm font-medium uppercase tracking-[0.16em] text-emerald-700">
              Loyal passkey lab
            </p>
            <h1 className="text-3xl font-semibold tracking-normal text-zinc-950 sm:text-4xl">
              Account integration demo
            </h1>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              disabled={!supportsPasskeys || pendingAction !== null}
              onClick={handleCreatePasskey}
              className="h-11 rounded-md bg-zinc-950 px-5 text-sm font-semibold text-white transition hover:bg-zinc-800 focus:outline-none focus:ring-4 focus:ring-zinc-300 disabled:cursor-not-allowed disabled:bg-zinc-300 disabled:text-zinc-600"
            >
              {pendingAction === "create-passkey" ? "Creating..." : "Create passkey"}
            </button>
            <button
              type="button"
              disabled={!supportsPasskeys || !selectedPasskey || pendingAction !== null}
              onClick={() => selectedPasskey && handlePasskeyLogin(selectedPasskey)}
              className="h-11 rounded-md border border-zinc-300 bg-white px-5 text-sm font-semibold text-zinc-900 transition hover:border-emerald-600 hover:text-emerald-800 focus:outline-none focus:ring-4 focus:ring-emerald-100 disabled:cursor-not-allowed disabled:border-zinc-200 disabled:text-zinc-400"
            >
              {pendingAction === "login-passkey" ? "Logging in..." : "Log in with passkey"}
            </button>
            <WalletLoginButton
              disabled={pendingAction !== null}
              pending={pendingAction === "login-wallet"}
              onPendingChange={setPendingAction}
              onResult={handleWalletResult}
              onError={(error) => setStatus({ tone: "error", message: getErrorMessage(error) })}
            />
          </div>

          <StatusMessage status={status} />
        </div>
      </section>

      <section className="mx-auto grid w-full max-w-6xl gap-6 px-5 py-6 sm:px-8 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="flex flex-col gap-4">
          <AccountPanel account={result.account} />
          <TransactionPanel transaction={result.transaction} />
        </div>

        <aside className="rounded-md border border-zinc-200 bg-zinc-50 p-4">
          <h2 className="text-sm font-semibold uppercase tracking-[0.14em] text-zinc-600">
            Local passkeys
          </h2>
          <div className="mt-4 flex flex-col gap-3">
            {storedPasskeys.length === 0 ? (
              <p className="rounded-md border border-dashed border-zinc-300 bg-white p-4 text-sm text-zinc-500">
                None
              </p>
            ) : (
              storedPasskeys.map((passkey) => (
                <article
                  key={passkey.credentialIdHash}
                  className="rounded-md border border-zinc-200 bg-white p-4"
                >
                  <h3 className="truncate text-sm font-semibold text-zinc-950">{passkey.label}</h3>
                  <p className="mt-1 break-all text-xs text-zinc-500">{passkey.authority}</p>
                </article>
              ))
            )}
          </div>
        </aside>
      </section>
    </main>
  );
}

function WalletLoginButton({
  disabled,
  pending,
  onPendingChange,
  onResult,
  onError,
}: {
  disabled: boolean;
  pending: boolean;
  onPendingChange: (action: string | null) => void;
  onResult: (response: WalletLoginResponse) => void;
  onError: (error: unknown) => void;
}) {
  const wallets = useWallets();
  const wallet = wallets.find(
    (candidate) =>
      candidate.features.includes("standard:connect") &&
      candidate.chains.some((chain) => chain.startsWith("solana:")),
  );

  if (!wallet) {
    return (
      <button
        type="button"
        disabled
        className="h-11 rounded-md border border-zinc-200 bg-zinc-50 px-5 text-sm font-semibold text-zinc-400"
      >
        Log in with wallet
      </button>
    );
  }

  return (
    <WalletConnectButton
      wallet={wallet}
      disabled={disabled}
      pending={pending}
      onPendingChange={onPendingChange}
      onResult={onResult}
      onError={onError}
    />
  );
}

function WalletConnectButton({
  wallet,
  disabled,
  pending,
  onPendingChange,
  onResult,
  onError,
}: {
  wallet: UiWallet;
  disabled: boolean;
  pending: boolean;
  onPendingChange: (action: string | null) => void;
  onResult: (response: WalletLoginResponse) => void;
  onError: (error: unknown) => void;
}) {
  const [isConnecting, connect] = useConnect(wallet);

  async function handleWalletLogin() {
    onPendingChange("login-wallet");

    try {
      const accounts = wallet.accounts.length > 0 ? wallet.accounts : await connect();
      const account = accounts.find((candidate) =>
        candidate.chains.some((chain) => chain.startsWith("solana:")),
      );

      if (!account) {
        throw new Error("No Solana account was returned by the wallet.");
      }

      onResult(await loginWithWalletAccount(account));
    } catch (error) {
      onError(error);
    } finally {
      onPendingChange(null);
    }
  }

  return (
    <button
      type="button"
      disabled={disabled || isConnecting}
      onClick={handleWalletLogin}
      className="h-11 rounded-md border border-zinc-300 bg-white px-5 text-sm font-semibold text-zinc-900 transition hover:border-emerald-600 hover:text-emerald-800 focus:outline-none focus:ring-4 focus:ring-emerald-100 disabled:cursor-not-allowed disabled:border-zinc-200 disabled:text-zinc-400"
    >
      {pending || isConnecting ? "Connecting..." : "Log in with wallet"}
    </button>
  );
}

function StatusMessage({ status }: { status: Status }) {
  const className =
    status.tone === "success"
      ? "border-emerald-200 bg-emerald-50 text-emerald-900"
      : status.tone === "error"
        ? "border-red-200 bg-red-50 text-red-900"
        : "border-zinc-200 bg-zinc-50 text-zinc-700";

  return <p className={`rounded-md border px-4 py-3 text-sm ${className}`}>{status.message}</p>;
}

function AccountPanel({ account }: { account: DemoAccount | null }) {
  return (
    <section className="rounded-md border border-zinc-200 bg-white p-4">
      <h2 className="text-sm font-semibold uppercase tracking-[0.14em] text-zinc-600">
        Account
      </h2>
      {account ? (
        <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
          <Field label="Kind" value={account.kind} />
          <Field label="Authority" value={account.authority} />
          <Field label="Authority record" value={account.authorityAddress} />
          <Field label="Squads settings" value={account.squadsSettings} />
          <Field label="Vault" value={account.vault} />
          <Field label="Vault index" value={String(account.vaultIndex)} />
        </dl>
      ) : (
        <p className="mt-4 rounded-md border border-dashed border-zinc-300 bg-zinc-50 p-4 text-sm text-zinc-500">
          None
        </p>
      )}
    </section>
  );
}

function TransactionPanel({ transaction }: { transaction: DemoTransactionEnvelope | null }) {
  return (
    <section className="rounded-md border border-zinc-200 bg-white p-4">
      <h2 className="text-sm font-semibold uppercase tracking-[0.14em] text-zinc-600">
        Transaction
      </h2>
      {transaction ? (
        <div className="mt-4 flex flex-col gap-3 text-sm">
          <Field label="Mode" value={transaction.mode} />
          <Field label="Fee payer" value={transaction.feePayer} />
          <Field label="Required signers" value={transaction.requiredSigners.join(", ")} />
          <Field label="Attached signers" value={transaction.attachedSigners.join(", ") || "None"} />
          <code className="block max-h-32 overflow-auto break-all rounded-md bg-zinc-100 px-3 py-2 text-xs text-zinc-700">
            {transaction.transactionBase64}
          </code>
        </div>
      ) : (
        <p className="mt-4 rounded-md border border-dashed border-zinc-300 bg-zinc-50 p-4 text-sm text-zinc-500">
          None
        </p>
      )}
    </section>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium uppercase tracking-[0.12em] text-zinc-500">{label}</dt>
      <dd className="mt-1 break-all text-zinc-900">{value}</dd>
    </div>
  );
}

function getErrorMessage(error: unknown) {
  if (error instanceof Error) {
    return error.message;
  }

  return "Unexpected demo error.";
}
