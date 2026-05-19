const LAMPORTS_PER_SOL = 1_000_000_000n;
const RENT_ACCOUNT_OVERHEAD_BYTES = 128n;
const RENT_LAMPORTS_PER_BYTE_YEAR = 3_480n;
const RENT_EXEMPTION_YEARS = 2n;

const USER_COUNT = 10_000n;
const VAULTS_PER_POOL = 256n;
const SQUADS_ONE_SIGNER_SETTINGS_BYTES = 168n;
const POOL_ALLOCATOR_BYTES = 101n;
const NORMAL_AUTHORITY_PDA_BYTES = 149n;

function rent(dataBytes) {
  return (
    (RENT_ACCOUNT_OVERHEAD_BYTES + dataBytes) *
    RENT_LAMPORTS_PER_BYTE_YEAR *
    RENT_EXEMPTION_YEARS
  );
}

function ceilDiv(numerator, denominator) {
  return (numerator + denominator - 1n) / denominator;
}

function decimal(lamports, digits = 9) {
  const whole = lamports / LAMPORTS_PER_SOL;
  const fraction = lamports % LAMPORTS_PER_SOL;
  return `${whole}.${fraction.toString().padStart(9, "0").slice(0, digits)}`;
}

function ratio(numerator, denominator, digits = 1) {
  return (Number(numerator) / Number(denominator)).toFixed(digits);
}

function percentReduction(baseline, candidate, digits = 2) {
  return ((1 - Number(candidate) / Number(baseline)) * 100).toFixed(digits);
}

const settingsRent = rent(SQUADS_ONE_SIGNER_SETTINGS_BYTES);
const allocatorRent = rent(POOL_ALLOCATOR_BYTES);
const normalAuthorityRent = rent(NORMAL_AUTHORITY_PDA_BYTES);
const poolCount = ceilDiv(USER_COUNT, VAULTS_PER_POOL);
const pooledCapacity = poolCount * VAULTS_PER_POOL;
const unusedPooledSlots = pooledCapacity - USER_COUNT;
const directSmartAccountRent = USER_COUNT * settingsRent;
const directWithNormalAuthorityRent = USER_COUNT * (settingsRent + normalAuthorityRent);
const pooledRent = poolCount * (settingsRent + allocatorRent);

console.log(`# Sponsorship Cost Simulation

Inputs:
- Users: ${USER_COUNT}
- Vault slots per pooled Squads settings account: ${VAULTS_PER_POOL}
- Pooled settings accounts needed: ${poolCount}
- Pooled smart-account capacity created: ${pooledCapacity}
- Unused slots in final pool: ${unusedPooledSlots}
- Rent formula: (128 + data_len) * 3,480 * 2 lamports

Per-account rent:
- Squads Settings, one Ed25519 signer: ${settingsRent} lamports / ${decimal(settingsRent)} SOL
- PoolAllocator Light PDA: ${allocatorRent} lamports / ${decimal(allocatorRent)} SOL
- Normal authority PDA sensitivity case: ${normalAuthorityRent} lamports / ${decimal(normalAuthorityRent)} SOL

Results:
| Route | Rent reserve |
| --- | ---: |
| Direct one-signer smart accounts | ${directSmartAccountRent} lamports / ${decimal(directSmartAccountRent)} SOL |
| Compressed user records + pooled smart accounts | ${pooledRent} lamports / ${decimal(pooledRent)} SOL |
| Direct smart accounts + normal authority PDA sensitivity | ${directWithNormalAuthorityRent} lamports / ${decimal(directWithNormalAuthorityRent)} SOL |

Savings:
- Pooled route vs direct one-signer smart accounts: ${ratio(directSmartAccountRent, pooledRent)}x less rent, ${percentReduction(directSmartAccountRent, pooledRent)}% reduction, ${decimal(directSmartAccountRent - pooledRent)} SOL not locked.
- Pooled route vs direct smart accounts plus normal authority PDAs: ${ratio(directWithNormalAuthorityRent, pooledRent)}x less rent, ${percentReduction(directWithNormalAuthorityRent, pooledRent)}% reduction, ${decimal(directWithNormalAuthorityRent - pooledRent)} SOL not locked.
- Pooled route actual per requested user: ${pooledRent / USER_COUNT} lamports / ${decimal(pooledRent / USER_COUNT)} SOL.
- Pooled route per created vault slot: ${Number(pooledRent) / Number(pooledCapacity)} lamports / ${Number(pooledRent) / Number(pooledCapacity) / 1_000_000_000} SOL.
`);
