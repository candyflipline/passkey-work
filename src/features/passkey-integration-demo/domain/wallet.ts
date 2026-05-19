import { address } from "@solana/kit";
import type { UiWalletAccount } from "@wallet-standard/react";
import { loginWallet } from "./api";

export async function loginWithWalletAccount(account: UiWalletAccount) {
  const walletAddress = address(account.address);

  return loginWallet({ walletAddress });
}
