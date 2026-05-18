import { PublicKey } from "@solana/web3.js";

export const PASSKEY_REGISTRY_PROGRAM_ID = new PublicKey(
  "rTvZY3rX9PBXyWzHtMRnY92o7EiEFSwsYZKoCLxUY9X",
);
export const SQUADS_SMART_ACCOUNT_PROGRAM_ID = new PublicKey(
  "SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG",
);
export const SECP256R1_PROGRAM_ID = new PublicKey(
  "Secp256r1SigVerify1111111111111111111111111",
);
export const LIGHT_ADDRESS_TREE_V2 = new PublicKey("amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx");

export const PASSKEY_AUTHORITY_SEED = "passkey-authority";
export const POOL_ALLOCATOR_SEED = "pool-allocator";
export const POOL_DIRECTORY_SEED = "pool-directory";
export const VERIFIER_SEED = "passkey-verifier";
export const SQUADS_SEED_PREFIX = "smart_account";
export const SQUADS_SEED_SETTINGS = "settings";
export const SQUADS_SEED_SMART_ACCOUNT = "smart_account";

export const REGISTRATION_DOMAIN = "LOYAL_PASSKEY_REGISTER_V1";
export const EXECUTION_DOMAIN = "LOYAL_PASSKEY_EXECUTE_V1";

export const SQUADS_EXECUTE_TRANSACTION_SYNC_V2_DISCRIMINATOR = new Uint8Array([
  90, 81, 187, 81, 39, 70, 128, 78,
]);

export const PASSKEY_AUTHORITY_DATA_LENGTH = 140;
