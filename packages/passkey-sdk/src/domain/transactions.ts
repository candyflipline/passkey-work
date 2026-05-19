import {
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  type Blockhash,
} from "@solana/web3.js";

export type PasskeyTransactionPlan = Readonly<{
  feePayer?: PublicKey;
  recentBlockhash?: Blockhash;
  instructions: readonly TransactionInstruction[];
  signers: readonly Keypair[];
}>;

export function createTransactionPlan(): PasskeyTransactionPlan {
  return {
    instructions: [],
    signers: [],
  };
}

export function setTransactionFeePayer(
  feePayer: PublicKey,
  plan: PasskeyTransactionPlan,
): PasskeyTransactionPlan {
  return {
    ...plan,
    feePayer,
  };
}

export function setTransactionLifetime(
  recentBlockhash: Blockhash,
  plan: PasskeyTransactionPlan,
): PasskeyTransactionPlan {
  return {
    ...plan,
    recentBlockhash,
  };
}

export function appendTransactionInstructions(
  instructions: readonly TransactionInstruction[],
  plan: PasskeyTransactionPlan,
): PasskeyTransactionPlan {
  return {
    ...plan,
    instructions: [...plan.instructions, ...instructions],
  };
}

export function addTransactionSigners(
  signers: readonly Keypair[],
  plan: PasskeyTransactionPlan,
): PasskeyTransactionPlan {
  return {
    ...plan,
    signers: [...plan.signers, ...signers],
  };
}

export function compileLegacyTransaction(plan: PasskeyTransactionPlan) {
  if (!plan.feePayer) {
    throw new Error("Set a fee payer before compiling the transaction.");
  }

  if (!plan.recentBlockhash) {
    throw new Error("Set a recent blockhash before compiling the transaction.");
  }

  const transaction = new Transaction({
    feePayer: plan.feePayer,
    recentBlockhash: plan.recentBlockhash,
  });

  transaction.add(...plan.instructions);

  return transaction;
}

export function signTransactionPlan(plan: PasskeyTransactionPlan) {
  const transaction = compileLegacyTransaction(plan);

  if (plan.signers.length > 0) {
    transaction.partialSign(...plan.signers);
  }

  return transaction;
}

export function buildUserPaidTransaction({
  authority,
  recentBlockhash,
  instructions,
}: {
  authority: Keypair;
  recentBlockhash: Blockhash;
  instructions: readonly TransactionInstruction[];
}) {
  return signTransactionPlan(
    addTransactionSigners(
      [authority],
      appendTransactionInstructions(
        instructions,
        setTransactionLifetime(
          recentBlockhash,
          setTransactionFeePayer(authority.publicKey, createTransactionPlan()),
        ),
      ),
    ),
  );
}

export function buildSponsoredTransactionForAuthority({
  sponsorFeePayer,
  authority,
  recentBlockhash,
  instructions,
}: {
  sponsorFeePayer: PublicKey;
  authority: Keypair;
  recentBlockhash: Blockhash;
  instructions: readonly TransactionInstruction[];
}) {
  return signTransactionPlan(
    addTransactionSigners(
      [authority],
      appendTransactionInstructions(
        instructions,
        setTransactionLifetime(
          recentBlockhash,
          setTransactionFeePayer(sponsorFeePayer, createTransactionPlan()),
        ),
      ),
    ),
  );
}

export function buildUnsignedSponsoredTransaction({
  sponsorFeePayer,
  recentBlockhash,
  instructions,
}: {
  sponsorFeePayer: PublicKey;
  recentBlockhash: Blockhash;
  instructions: readonly TransactionInstruction[];
}) {
  return compileLegacyTransaction(
    appendTransactionInstructions(
      instructions,
      setTransactionLifetime(
        recentBlockhash,
        setTransactionFeePayer(sponsorFeePayer, createTransactionPlan()),
      ),
    ),
  );
}
