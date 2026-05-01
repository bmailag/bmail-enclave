# bmail enclaves (verifiable SGX)

```
                   ▁       ▗▌
                   ▝▙▁  ▙  ▐▊ ▗▌ ▃▛
                ▗▁▗ ▜█▃ ▜▙ ██▕█▆▀█ ▂ ▂▞
              ▃▁ ▜▇▉ ██▙▝▊▗██▕▛▘▗▙▇▉▇▀ ▂▄▖
            ▁  ▀▇▅▂▀▚▝██▙ ▐██ ▗ ▟█▀▘▃▆█▛▔▁▂
             ▝▚▄▝▜█▇▃ ▜██▌▐██▗▍▗▀▂▅██▛▔▄▀▔
            ▗▆▅▟▛ ▂▃▃▂ ███▕██▛ ▗▟▛▀▂▂▁▀▜█▛▀▀▔
         ▁▂▃▃▃▂▔▖▜▄▅▄▛▜▃▀▀▎▜█  ▀▗▆▜▙▄▟▀▄ ▅▅▄▃▂▁
        ▔▔▔▀▀█▎▞▟▘  ▗▖▚▜▆██▞▚▆█▅▛▟▚▃  ▀▖▚▐▛▔▔▔▔
         ▗▆▀▀▜▕▍▌   ▔▔▐▐████████▌▍▝▀   ▐▐ ▀▀▀▘
           ▂▖ ▅▙▀▂   ▂▝▟█▛▜██▀██▙▚▁   ▗▘▟▖▜▅▂
          ▝▀ ▄▀██▅█▇█▅████▆██▆███▇▟▇▇▇▅██▀ ▔▀▘
             ▜█▅▛▀████████████████████▀▜▅█ ▚▖
              ▀███▇▇▇▇▇▇▇▆▆▅▅▅▆▆▆▆▆▆▆▆██▛▘  ▔
            ▂▃▄ ▃▃▀▀▜████████████████▛▀▔
         ▃▆█▛▀▀ ▀▀▜█▆▃▔▜▀▀▀▀▀▀▀▀▀█▃▄▅▇█▍
       ▗▅▔▘        ▔▀▃▙▞▜████████████▌▜▄▇▏
      ▗█▛            ▝▜█ ▜████████▀▔▔▁ █▎
      ▟▊              ▝█▋▝█████████▛▀▀  ▁▂▁
     ▕▁▋    ▁▇▇▇▇▁▎    ▍▊ ▀▀▀▀▀▜█▌     ▝▔▉▔▌
      █▊    ▐█▌ ██▎   ▗█▋ ▕▘  ▐        ▔▔▔▀▘
      ▝█▖   ▔▐▙▅▛▔▏   ▟▛ ▃▕▎  ▝▁▂▂▃▃▖ ▗▇▇▆▖
       ▝▛▘▂         ▂▀▛ ▃▀▀▀▀▀▀▀▀██▃  ▔▟▀▜▘
         ▀▜▇▅▄▃ ▃▄▆█▀▘▗▇█▍      ██▃▔
           ▔▔▀▘▝▀▀▔▁▅ ▇██▌     ▕███▆▆▅ ▂
                   ▀ ▀▀▔▔       ▔▔▀▀▘▝▘▔
```

This repository contains the source code that runs inside the five
Intel SGX enclaves backing [bmail.ag](https://bmail.ag):

| Enclave | What it does |
|---|---|
| `gateway` | TLS terminator + reverse proxy for `bmail.ag`. Issues remote attestation reports binding the served TLS public key to the enclave measurement. |
| `smtp-inbound` | Receives inbound SMTP at `smtp.bmail.ag`, verifies SPF/DKIM/DMARC, runs the spam classifier, encrypts the message to the recipient's epoch key, and writes it to durable storage — all inside SGX so plaintext never leaves the enclave. |
| `smtp-outbound` | Signs outbound mail with DKIM and delivers it. Pulls the active DKIM pool key from `keystore` over attested mTLS at startup; never writes the key to disk. |
| `payment` | Mints Fake ID credentials. Atomic slot consumption, RSA blind signatures, all sealed. |
| `keystore` | Long-lived, intentionally-frozen enclave that holds DKIM and other long-lived secrets. Hands keys to peer enclaves only after verifying their MRENCLAVE matches an allow-list. Designed to almost never change so its measurement stays stable across the lifetime of the secrets it holds. |

The point of publishing it is to let anyone reproduce the **exact**
enclave binaries that bmail.ag is running, hash them, and compare to
the MRENCLAVE values in the latest attestation report served at
`https://bmail.ag/.well-known/sgx-quotes/`. If the rebuilt MRENCLAVE
matches the live MRENCLAVE, you have proof that the code reading
plaintext mail inside the SGX enclave is **byte-identical** to the code
in this repository.

## Build it yourself

You need Linux + the EGo SDK at version 1.8.1. The byte output of
`ego-go build` depends on the build host, so a macOS or Windows host
will not match the published Linux MRENCLAVE. To reproduce on a
non-Linux machine, use Docker:

```
git clone https://github.com/bmailag/bmail-enclave.git
cd bmail-enclave
docker run --rm -v "$PWD":/src -w /src ghcr.io/edgelesssys/ego-dev:v1.8.1 make all
```

On Linux with EGo 1.8.1 installed natively, the Docker step is
unnecessary:

```
git clone https://github.com/bmailag/bmail-enclave.git
cd bmail-enclave
make all
```

`make all` builds and signs all five enclaves with a throwaway
signing key (signing key only affects MRSIGNER, not MRENCLAVE), then
prints the five MRENCLAVE values. Each value should match the
corresponding file in `enclave/mrenclaves/`. Mismatch means **either**
your build host produced different bytes (different EGo version, glibc
version, etc.) **or** the published expected value is stale.

## Verifying what bmail.ag is running

`https://bmail.ag/.well-known/sgx-quotes/{name}` returns the live
attestation quote for each running enclave. The browser-side `/verify`
page on bmail.ag fetches all five, validates them against Intel's
attestation chain (PCS), and compares the measurements to the values
in this repository.

You can run the same check by hand:

```
curl -s https://bmail.ag/.well-known/sgx-quotes/gateway \
  | jq -r .enclave_measurement
# expected: contents of enclave/mrenclaves/gateway.super.mrenclave
```

(`gateway.super` because production runs on the SGX2 super-server with
the larger heap; the `gateway.mrenclave` value is the SGX1 variant
shipped to dev/staging hosts.)

## What's in here

```
cmd/                       Enclave entry points (5 main packages).
internal/                  Every internal Go package transitively pulled
                           into one or more enclave compilations. Nothing
                           else — backend HTTP services, billing, IAP,
                           Stripe, push notifications, etc. all live in
                           the closed-source repo and are NOT published.
enclave/*.json             EGo enclave configs. heapSize, productID, and
                           securityVersion all flow into MRENCLAVE.
enclave/mrenclaves/        Expected MRENCLAVE per enclave. Must match
                           `make all` output.
.github/workflows/build.yml CI verification: rebuilds + asserts MRENCLAVE.
Makefile                   Reproducible build commands.
LICENSE.md                 SAFE license + reproducibility verification
                           and publication-of-findings addenda.
SECURITY.md                Threat model, in-scope and out-of-scope
                           security claims, vulnerability reporting.
```

## License

Source Available For Examination (SAFE) — see [LICENSE.md](LICENSE.md).
Inspection / audit / non-commercial research permitted; redistribution,
production deployment, and commercial use require prior written
approval from VP.net LLC.

Two addenda apply to this repository specifically:

  - **§15 (reproducibility)** — building from this source to verify
    that your rebuilt MRENCLAVE matches the live one served at
    bmail.ag is permitted without prior approval. That's the entire
    point of publication.
  - **§16 (publication of findings)** — you may publish your
    independent analysis, audit notes, blog posts, conference talks,
    or academic papers describing what you observed in this source
    without prior approval, so long as you give a private heads-up at
    least 7 days before publishing anything that names a specific
    unfixed vulnerability. Routine cryptographic critique, design
    commentary, "I tried to break it and here's what I found"
    write-ups — no approval, no embargo, no review. The pitch is only
    honest if reviewers can talk about what they read.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md) for the threat model and the disclosure
process. The short version: report to security@vp.net, give us 60
days before naming an unfixed vulnerability publicly, and the
publication-of-findings carve-out (§16 above) covers everything else.

## Main project

The bmail product, infrastructure, and full source live elsewhere.
This repository is the verifiable enclave subset.
