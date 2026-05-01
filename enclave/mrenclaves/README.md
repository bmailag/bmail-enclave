# Expected MRENCLAVE values

Each `<service>.mrenclave` file in this directory holds the SHA-256
identity (Intel SGX MRENCLAVE) that the corresponding enclave binary
**must** measure to when built from this commit by the GitLab CI
`build:enclave:<service>` job.

## Why

MRENCLAVE is the cryptographic measurement of an enclave's loaded
image (code + initial data + per-enclave config such as `heapSize`,
`stackSize`, `productID`, `securityVersion`). It does **not** include
the signing key (that's MRSIGNER, in SIGSTRUCT). So MRENCLAVE is
deterministic across two independent builders given:

  - The same source tree
  - The same EGo version (currently pinned to `v1.8.1` via
    `ghcr.io/edgelesssys/ego-dev:v1.8.1`)
  - The same `enclave/<service>.json` config
  - The same Go build flags (`-trimpath -ldflags="-s -w -buildid="`)

This is what makes "rebuild and verify the running enclave" possible
for outside auditors: anyone with the published source can produce
the exact same MRENCLAVE and check it against the live attestation
report bmail.ag serves.

## How the assertion works

The `build:enclave:<service>` jobs run `ego sign` then `ego uniqueid`
and write the measured MRENCLAVE to `build/enclave/<service>.mrenclave`.
A subsequent step compares that against this directory's checked-in
expected value. **Mismatch fails CI.**

## When to update

Every legitimate enclave-source change re-measures MRENCLAVE — **that
is by design**. After making such a change, the dev workflow is:

  1. Push the source change.
  2. CI's `build:enclave:<service>` job runs and fails with the new
     measured MRENCLAVE printed.
  3. Update this directory's `<service>.mrenclave` file with the new
     value, commit, push.
  4. CI now passes.

## When MRENCLAVE-based sealing lands

Once the Stage E seal-policy flip is live (`SealWithProductKey` →
`SealWithUniqueKey`), updating an MRENCLAVE here also triggers the
production deploy ceremony: TLSA rotation for gateway/smtp-inbound,
DKIM selector rotation for smtp-outbound, all coordinated against the
DNS update window. Until Stage E lands the assertion is just a
regression guard.

## SGX1 vs super-server (SGX2) variants

`gateway.json` / `smtp-inbound.json` configure SGX1-safe heaps for
fullxp + Box-1/Box-4. `gateway.super.json` / `smtp-inbound.super.json`
inflate `heapSize` for the super-server's SGX2 EPC. Heap is part of
MRENCLAVE, so the `.super` variants land at different measurements
and are tracked here as separate `*.super.mrenclave` files.
