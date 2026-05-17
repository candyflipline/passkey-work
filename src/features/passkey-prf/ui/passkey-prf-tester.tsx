"use client";

import { useEffect, useMemo, useState } from "react";
import {
  createPasskeyForAddress,
  findExistingPasskeyForAddress,
  isWebAuthnSupported,
  normalizeAddress,
  testPasskeyPrf,
  type StoredPasskey,
} from "../domain/webauthn";
import { listStoredPasskeysForAddress, saveStoredPasskey } from "../domain/storage";

type Status = {
  tone: "idle" | "success" | "error";
  message: string;
};

export function PasskeyPrfTester() {
  const [address, setAddress] = useState("");
  const [status, setStatus] = useState<Status>({
    tone: "idle",
    message: "Enter an address to view local passkeys or create a new one.",
  });
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [lastPrfOutput, setLastPrfOutput] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);
  const [supported, setSupported] = useState(false);
  const [, setStorageRevision] = useState(0);

  const cleanAddress = useMemo(() => normalizeAddress(address), [address]);
  const savedPasskeys = hydrated ? listStoredPasskeysForAddress(cleanAddress) : [];

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setHydrated(true);
      setSupported(isWebAuthnSupported());
    }, 0);

    return () => window.clearTimeout(timer);
  }, []);

  async function handleCreate() {
    setPendingAction("create");
    setStatus({ tone: "idle", message: "Opening the browser passkey prompt..." });
    setLastPrfOutput(null);

    try {
      const passkey = await createPasskeyForAddress(cleanAddress);
      saveStoredPasskey(passkey);

      setStorageRevision((revision) => revision + 1);
      setStatus({
        tone: "success",
        message:
          passkey.prfEnabled === false
            ? "Passkey created, but this authenticator did not enable PRF."
            : "Passkey created and saved for this address.",
      });
    } catch (error) {
      setStatus({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setPendingAction(null);
    }
  }

  async function handleFindExisting() {
    setPendingAction("find");
    setStatus({ tone: "idle", message: "Opening the browser passkey chooser..." });
    setLastPrfOutput(null);

    try {
      const result = await findExistingPasskeyForAddress(cleanAddress);

      saveStoredPasskey(result.passkey);
      setStorageRevision((revision) => revision + 1);
      setLastPrfOutput(result.prfFirst);
      setStatus({
        tone: "success",
        message: result.prfFirst
          ? "Existing passkey selected, saved locally, and PRF output returned."
          : "Existing passkey selected and saved locally. No PRF output was returned.",
      });
    } catch (error) {
      setStatus({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setPendingAction(null);
    }
  }

  async function handleTestPrf(passkey: StoredPasskey) {
    setPendingAction(passkey.id);
    setStatus({ tone: "idle", message: "Requesting a PRF evaluation from that passkey..." });
    setLastPrfOutput(null);

    try {
      const result = await testPasskeyPrf(passkey);

      setLastPrfOutput(result.prfFirst);
      setStatus({
        tone: result.prfFirst ? "success" : "error",
        message: result.prfFirst
          ? "PRF evaluation returned deterministic output for this address salt."
          : "This browser or authenticator completed auth but did not return PRF output.",
      });
    } catch (error) {
      setStatus({ tone: "error", message: getErrorMessage(error) });
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <section className="mx-auto flex min-h-screen w-full max-w-5xl flex-col gap-8 px-5 py-8 sm:px-8 lg:py-12">
      <header className="flex flex-col gap-3 border-b border-zinc-200 pb-6">
        <p className="text-sm font-medium uppercase tracking-[0.18em] text-emerald-700">
          Loyal passkey lab
        </p>
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_18rem] lg:items-end">
          <div>
            <h1 className="text-3xl font-semibold tracking-normal text-zinc-950 sm:text-4xl">
              Passkey PRF tester
            </h1>
            <p className="mt-3 max-w-2xl text-base leading-7 text-zinc-600">
              Create a discoverable passkey scoped to an address, or select an existing
              passkey for this domain and save its credential ID locally.
            </p>
          </div>
          <div className="rounded-md border border-zinc-200 bg-zinc-50 px-4 py-3 text-sm text-zinc-700">
            {supported
              ? "WebAuthn APIs are available in this browser."
              : "This browser does not expose the WebAuthn APIs needed here."}
          </div>
        </div>
      </header>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_24rem]">
        <div className="flex flex-col gap-5">
          <label className="flex flex-col gap-2">
            <span className="text-sm font-medium text-zinc-800">Address</span>
            <input
              value={address}
              onChange={(event) => {
                setAddress(event.target.value);
                setLastPrfOutput(null);
              }}
              placeholder="0x..., Solana address, wallet handle, or test user ID"
              className="h-12 rounded-md border border-zinc-300 bg-white px-4 text-base text-zinc-950 outline-none transition focus:border-emerald-600 focus:ring-4 focus:ring-emerald-100"
            />
          </label>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              disabled={!supported || !cleanAddress || pendingAction !== null}
              onClick={handleCreate}
              className="h-11 rounded-md bg-zinc-950 px-5 text-sm font-semibold text-white transition hover:bg-zinc-800 focus:outline-none focus:ring-4 focus:ring-zinc-300 disabled:cursor-not-allowed disabled:bg-zinc-300 disabled:text-zinc-600"
            >
              {pendingAction === "create" ? "Creating..." : "Create passkey"}
            </button>
            <button
              type="button"
              disabled={!supported || !cleanAddress || pendingAction !== null}
              onClick={handleFindExisting}
              className="h-11 rounded-md border border-zinc-300 bg-white px-5 text-sm font-semibold text-zinc-900 transition hover:border-emerald-600 hover:text-emerald-800 focus:outline-none focus:ring-4 focus:ring-emerald-100 disabled:cursor-not-allowed disabled:border-zinc-200 disabled:text-zinc-400"
            >
              {pendingAction === "find" ? "Finding..." : "Use existing passkey"}
            </button>
            <p className="text-sm text-zinc-500">
              Existing passkeys are selected through the browser chooser for this domain.
            </p>
          </div>

          <StatusMessage status={status} />

          {lastPrfOutput ? (
            <div className="rounded-md border border-emerald-200 bg-emerald-50 p-4">
              <p className="text-sm font-medium text-emerald-950">Latest PRF output</p>
              <code className="mt-2 block break-all rounded bg-white px-3 py-2 text-xs text-emerald-950">
                {lastPrfOutput}
              </code>
            </div>
          ) : null}
        </div>

        <aside className="rounded-md border border-zinc-200 bg-zinc-50 p-4">
          <h2 className="text-sm font-semibold uppercase tracking-[0.16em] text-zinc-600">
            Local passkeys
          </h2>

          <div className="mt-4 flex flex-col gap-3">
            {savedPasskeys.length === 0 ? (
              <p className="rounded-md border border-dashed border-zinc-300 bg-white p-4 text-sm leading-6 text-zinc-500">
                {cleanAddress
                  ? "No saved passkeys for this address in this browser yet."
                  : "Enter an address to load saved passkeys."}
              </p>
            ) : (
              savedPasskeys.map((passkey) => (
                <PasskeyRow
                  key={`${passkey.address}:${passkey.id}`}
                  passkey={passkey}
                  pending={pendingAction === passkey.id}
                  disabled={!supported || pendingAction !== null}
                  onTest={() => handleTestPrf(passkey)}
                />
              ))
            )}
          </div>
        </aside>
      </div>
    </section>
  );
}

function PasskeyRow({
  passkey,
  pending,
  disabled,
  onTest,
}: {
  passkey: StoredPasskey;
  pending: boolean;
  disabled: boolean;
  onTest: () => void;
}) {
  return (
    <article className="rounded-md border border-zinc-200 bg-white p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-zinc-950">{passkey.label}</h3>
          <p className="mt-1 text-xs text-zinc-500">
            Created {new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(passkey.createdAt))}
          </p>
        </div>
        <PrfBadge enabled={passkey.prfEnabled} />
      </div>

      <code className="mt-3 block break-all rounded bg-zinc-100 px-3 py-2 text-xs text-zinc-600">
        {passkey.id}
      </code>

      <button
        type="button"
        disabled={disabled}
        onClick={onTest}
        className="mt-4 h-10 w-full rounded-md border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-900 transition hover:border-emerald-600 hover:text-emerald-800 focus:outline-none focus:ring-4 focus:ring-emerald-100 disabled:cursor-not-allowed disabled:border-zinc-200 disabled:text-zinc-400"
      >
        {pending ? "Checking..." : "Test PRF"}
      </button>
    </article>
  );
}

function PrfBadge({ enabled }: { enabled: boolean | null }) {
  if (enabled === null) {
    return <span className="rounded bg-zinc-100 px-2 py-1 text-xs text-zinc-500">PRF unknown</span>;
  }

  return (
    <span
      className={
        enabled
          ? "rounded bg-emerald-100 px-2 py-1 text-xs text-emerald-800"
          : "rounded bg-amber-100 px-2 py-1 text-xs text-amber-800"
      }
    >
      {enabled ? "PRF ready" : "No PRF"}
    </span>
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

function getErrorMessage(error: unknown) {
  if (error instanceof Error) {
    return error.message;
  }

  return "Something went wrong while talking to the browser passkey API.";
}
