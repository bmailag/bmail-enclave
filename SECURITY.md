# Security model & threat model

This document describes what the published source in
`bmailag/bmail-enclave` is intended to prove, what it does **not**
prove, and how to report security findings.

## What this repository proves

The enclaves in this repo are the only code paths inside `bmail.ag`
that ever see plaintext mail, the long-lived DKIM keys, the active TLS
private keys, or the Fake ID minting state. By publishing this source
plus the corresponding `MRENCLAVE` measurements, and by serving live
SGX attestation quotes at `https://bmail.ag/.well-known/sgx-quotes/`,
we let any third party verify the following chain end-to-end:

  1. The byte sequence of the binary inside the running SGX enclave
     (proven by `MRENCLAVE` in the attestation quote, signed by Intel).
  2. The byte sequence built locally from this source on the pinned
     EGo SDK (verified by reproducing `make all`).
  3. The byte sequences match, therefore the code reading plaintext
     mail in production is byte-identical to the code in this repo.

If both byte sequences match, the only thing left to trust is what
the code in this repo actually does. That is the part this repo
exists to make publicly auditable.

## In-scope security claims

The following claims are considered fair targets for analysis. If you
find that any of these does not actually hold, we want to hear from
you (see "Reporting" below):

  - **Plaintext containment.** Plaintext mail bodies, plaintext
    attachments, plaintext addressing of in-flight mail, and OPAQUE
    password material never leave the SGX enclave boundary in
    plaintext. Persisted ciphertext is encrypted with keys that the
    enclave seals to its own measurement.
  - **Long-lived key custody.** DKIM signing keys, the long-lived
    enclave-internal certificate authority key (if any), and any
    other secret marked "long-lived" are held only inside the
    `keystore` enclave. They are released to peer enclaves only after
    the keystore verifies the peer's `MRENCLAVE` against an explicit
    allow-list baked into the keystore source. They are never written
    to disk in plaintext, never logged, never returned to a network
    caller that does not present a matching attested mTLS identity.
  - **TLS-key custody.** The live TLS private keys served to browsers
    and SMTP peers are generated inside the `gateway` and
    `smtp-inbound` enclaves, are sealed to those enclaves'
    measurements, and are bound into attestation reports so that a
    third party can verify the TLS public key was produced inside the
    measured enclave.
  - **DKIM signing custody.** Outbound mail is DKIM-signed inside the
    `smtp-outbound` enclave with keys fetched at startup from
    `keystore` over attested mTLS. The signing key is never written
    to disk on the `smtp-outbound` host and never appears in logs.
  - **Reproducibility of measurements.** Building this source on the
    pinned EGo SDK on a Linux x86_64 host produces the byte-identical
    enclave binaries whose `MRENCLAVE` values are recorded in
    `enclave/mrenclaves/`.
  - **Attestation freshness.** The SGX quotes served at
    `/.well-known/sgx-quotes/` are produced by the live enclave,
    include a freshness binding, and chain to an Intel-signed
    quoting enclave.
  - **Allow-list integrity.** The `MRENCLAVE` allow-list in the
    `keystore` source code is the only thing that decides who can
    fetch a long-lived secret. There is no environment variable,
    config file, or runtime hook that can override it; changing the
    allow-list requires a new keystore build, which produces a new
    keystore `MRENCLAVE`, which is itself externally observable.

If your analysis shows that one of these claims is contradicted by
the actual code in this repo, that is a finding worth a post.

## Out-of-scope security claims

The following are **not** in scope for the byte-equivalence guarantee
this repo provides. They are real concerns and we take them
seriously, but they are not what publishing this source is meant to
prove:

  - **Side channels in SGX.** Cache-timing, page-table, branch
    predictor, speculative execution, and microarchitectural side
    channels against Intel SGX are an active research area. We
    follow the public mitigation guidance from Intel (microcode
    updates, mitigations enabled in EGo, no shared resources with
    untrusted tenants) but cannot prove the absence of side-channel
    leakage.
  - **Hardware compromise of Intel SGX.** Physical attacks on the
    CPU package, glitching, fault injection, attacks on the
    Memory Encryption Engine, or compromise of Intel's signing keys
    used for quoting enclaves are out of scope. SGX is the
    hardware-level trust root and we inherit its security
    assumptions.
  - **Microcode and platform firmware bugs.** Bugs in the SGX
    runtime (EGo, the Intel-provided QE/PCE/PCK chain), in CPU
    microcode, or in platform firmware (BIOS/SMM/ME) are out of
    scope for our measurement claim. We track Intel SA notices and
    bump EGo / microcode when patches are available.
  - **Linux kernel and host OS bugs.** SGX defends the enclave from a
    compromised kernel for confidentiality, but a kernel compromise
    can deny service, observe network metadata, and influence
    timing. Defending against a compromised host kernel is not
    something this repo can prove.
  - **Operational compromise of the colocation facility.** Physical
    access to the bare-metal hosts could allow rebooting them into
    a non-SGX or simulation mode. Clients defend against this by
    refusing to talk to enclaves whose attestation quote does not
    match an expected `MRENCLAVE`; they should not assume the host
    OS itself is honest.
  - **Closed-source services outside the enclave perimeter.** The
    backend HTTP service, the worker, the auth service, the KT
    service, the billing path (Stripe webhooks, IAP, voucher
    redemption), and all of the database and queue plumbing live
    outside the SGX trust boundary and are **not** published here.
    They handle ciphertext and metadata; they do not handle
    plaintext mail or long-lived enclave secrets. They are
    deliberately out of scope for the verifiable-crypto pitch.
  - **Metadata exposure.** The fact that user A sent a message of
    size N to recipient B at time T is observable to the host OS,
    the network, and any logging the backend chooses to keep. The
    SGX enclaves protect the body of the message, not its existence.
  - **Compromise of customer endpoints.** If a customer's browser,
    operating system, or recovery mnemonic is compromised, no
    server-side guarantee can save them. Endpoint security is the
    customer's responsibility.

## Reporting vulnerabilities

Email `security@vp.net` for any finding that names a specific
previously-undisclosed vulnerability in the running production
enclaves.

The license addendum at LICENSE.md §16 spells out the publication
rules in detail; the short version is:

  - Independent analysis, design critique, blog posts, conference
    talks, academic papers — no approval, no embargo, no review.
    Publish freely.
  - Specific, exploitable, undisclosed vulnerability in production —
    please notify `security@vp.net` at least 60 days before
    publication so we can remediate and rotate `MRENCLAVE`.
  - If we fail to remediate within 60 days, the embargo lapses and
    you may publish anyway.

We do not run a paid bug bounty program at this time. If you would
like a public acknowledgement (or explicit non-acknowledgement, if
you would rather stay anonymous), say so when you report.

## Responsible disclosure expectations on our side

If a vulnerability you report is fixed by a new enclave build:

  - We will publish the new `MRENCLAVE` values in
    `enclave/mrenclaves/` in this repo and roll the live enclaves to
    measurements that include the fix.
  - We will credit you in the release notes unless you ask us not
    to.
  - We will not name you publicly without your consent.
  - We will not claim privately or publicly that you violated this
    license by reporting the issue. The whole point of this repo is
    that you are allowed to look.
