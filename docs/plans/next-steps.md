# Next Steps

Future work for the pooled authority registry. Keep this short.

## Open Items

Run a simulation on 10,000 accounts. It should stress allocator rollover and proof packing at a scale closer to production.

Decide how the registry and allocator should protect against spam before any public path sponsors account creation or subsidizes registrations.

Find the cheapest way to store or advance nonces without recalculating compressed state every time.

Define per-vault limits. Then enforce them in the registry path.
