import { Connection } from "@solana/web3.js";

import { MAGICBLOCK_DEVNET_RPC_URL, MAGICBLOCK_LOCAL_RPC_URL } from "./constants";

const endpointByCluster = {
  devnet: MAGICBLOCK_DEVNET_RPC_URL,
  localnet: MAGICBLOCK_LOCAL_RPC_URL,
} as const;

type MagicBlockCluster = keyof typeof endpointByCluster;

const cachedConnections = new Map<MagicBlockCluster, Connection>();

export const getMagicBlockConnection = (
  cluster: MagicBlockCluster = "devnet"
): Connection => {
  const cachedConnection = cachedConnections.get(cluster);
  if (cachedConnection) return cachedConnection;

  const connection = new Connection(endpointByCluster[cluster], {
    commitment: "confirmed",
  });
  cachedConnections.set(cluster, connection);

  return connection;
};
