import { address } from "@solana/kit";
import { PublicKey } from "@solana/web3.js";
import {
  createWalletAccount,
  getDemoStore,
} from "@/features/passkey-integration-demo/server/demo-store";
import { buildBackendSponsoredWalletEnvelope } from "@/features/passkey-integration-demo/server/demo-transactions";
import { jsonError, readJson } from "@/features/passkey-integration-demo/server/http";
import type {
  WalletLoginRequest,
  WalletLoginResponse,
} from "@/features/passkey-integration-demo/types";

export async function POST(request: Request) {
  try {
    const input = await readJson<WalletLoginRequest>(request);
    const walletAddress = address(input.walletAddress);
    const publicKey = new PublicKey(walletAddress);
    const store = getDemoStore();
    const existing = store.walletsByAddress.get(publicKey.toBase58());

    if (existing) {
      return Response.json({
        account: existing,
        status: "found",
        transaction: buildBackendSponsoredWalletEnvelope(publicKey),
      } satisfies WalletLoginResponse);
    }

    const account = await createWalletAccount(publicKey);

    return Response.json({
      account,
      status: "needs-create",
      transaction: buildBackendSponsoredWalletEnvelope(publicKey),
    } satisfies WalletLoginResponse);
  } catch (error) {
    return jsonError(error);
  }
}
