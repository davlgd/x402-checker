# x402-checker

Checks whether an HTTP resource server conforms to the [x402](https://github.com/x402-foundation/x402) protocol, version 2, and how far. Every verdict names the requirement it measures and the clause behind it, so a failure can be argued against the specification text rather than against the tool's opinion.

The tool was written from the specification alone (a pinned copy is in `spec/`, upstream commit `59f1347a`, also stamped in every report; the EIP-3009 text one check cites is pinned in `spec/external/`). It pays with the `exact` scheme on an EVM network with EIP-3009 authorizations, the only mechanism it holds a key for. Offers of `exact` on Solana are inspected by `probe` (fee payer, base58 keys, hints) and driven end to end by `scenarios --mechanism svm` against the scripted facilitator, with random bytes standing for the transaction; `pay` cannot pay them. Anything else is reported as *cannot assess*, never as a failure.

## Getting the binary

Prebuilt binaries for macOS, Linux and Windows are attached to each [GitHub release](https://github.com/davlgd/x402-checker/releases), each with its SHA-256. From a clone, `cargo install --path crates/x402-checker` puts `x402-checker` on your `PATH`; `cargo build --release` leaves it in `target/release/`. Rust 1.98 or later.

## Three ways to look at a server

| Command | What it needs | What it shows |
|---|---|---|
| `probe URL` | nothing | the 402 signal and its terms, malformed payment headers, a payment that cannot be valid |
| `pay URL` | a funded test wallet (`X402_PAYER_KEY`) | one real payment through the server's own facilitator, read back on chain (the transaction, the transfer, the tool's own nonce consumed), then a replay and authorizations that must be refused |
| `scenarios URL` | the server configured to use the tool's facilitator (and, ideally, its witness as upstream) | every settlement outcome: valid, invalid, rejected, pending, unreadable, failing resource, replay; the order and content of the server's calls; how the server authenticates to its facilitator. `--mechanism svm` drives the same scenarios through the server's Solana offer |

`all URL` runs `probe` then `pay`; `serve` hosts the facilitator and the witness for a manual session; `ledger TX_HASH` reads the chain for a settlement already made, with the same checks `pay` runs after its payment; it is always strict, so a transfer or binding it cannot demonstrate is an incomplete result (exit code 2).

```sh
# no funds, no cooperation
x402-checker probe https://api.example.com/premium

# one payment on Base Sepolia (test wallets only), then the chain is read; the key comes from the environment,
# here typed without echo so that it stays out of the shell history
read -rs X402_PAYER_KEY && export X402_PAYER_KEY
x402-checker pay https://api.example.com/premium --max-amount 100000

# a settlement from an earlier receipt, checked on chain again without paying (a template: fill in the
# transaction hash and the offer's asset, payTo, amount and payer, plus the nonce when known)
x402-checker ledger <tx hash> --asset <mint or contract> --pay-to <address> --amount 10000 --payer <address> --nonce <32 bytes hex>

# the server must reach both doubles: here it runs on another host, so both listen on every interface and the
# server is configured with facilitator http://<this host>:4020 and upstream http://<this host>:4021; a server on
# the same machine can keep the 127.0.0.1 defaults
x402-checker scenarios https://api.example.com/premium --facilitator-listen 0.0.0.0:4020 --witness-listen 0.0.0.0:4021 --pause

# machine-readable report for CI, strict about coverage
x402-checker all https://api.example.com/premium --format json -o report.json --strict
```

Requests can carry the method, headers and body the resource expects (`-X POST -H 'Authorization: Bearer …' -d '{}'`).

## Reading a report

Each line is one check: a verdict, the requirement id, the title and the level.

```
  PASS HTTP-001     an unpaid request is answered with status 402  (required)
  WARN HTTP-010s    a malformed PAYMENT-SIGNATURE is answered with status 400  (recommended)
       not base64 -> 402; base64 of plain text -> 402
       spec: transports-v2/http.md, Error Handling: "Invalid Payment | 400 | Malformed payment payload or requirements"
       note: the same table maps Payment Failed to 402, so a 402 with a fresh challenge is defensible; the tool warns rather than fails
```

- **Levels.** `required` comes from a MUST, a Required field or prescriptive prose: a failure means not conformant. `recommended` comes from a SHOULD or a policy the tool names as such: a failure is a warning. `optional` comes from a MAY or an example: information only, never judged.
- **Verdicts.** `PASS`, `FAIL`, `WARN`, `INFO`, `SKIP` (a precondition on the tool's side was missing, such as a payer key or a witness), `N/A` (the target is outside what the check can judge) and `BLOCK` (the observation is not attributable to the target: a dependency, the tool, or an ambiguous outcome).
- **Attribution.** A `FAIL` names who is responsible: the target, a dependency (a real facilitator, an RPC node, a wallet balance) or the tool. Only target failures count against conformance; the others are listed as not demonstrated.
- **Scope.** A run reports what it observed in the suites it executed and lists the required checks it did not demonstrate; suites not run are listed with the reason. Checks of a payment family the server does not offer (the EVM checks on a Solana-only server, the Solana checks on an EVM-only one) are *cannot assess* and, with `--strict`, appear in that list: *incomplete* then means the tool's whole scope was not exercised, never that the server had to offer that family. `probe` alone says nothing about payments or call order. Exit codes: `0` no required failure in the executed scope, `1` at least one, `2` nothing could be graded, or (with `--strict`) required checks left undemonstrated: the run is *incomplete*, which is not a verdict against the server.

Ids point at rows of [`docs/requirements.md`](docs/requirements.md) (`CORE-002`, `HTTP-003`, `EVM-012`). A letter suffix marks a check derived from that row; `PAY-`, `PROBE-`, `SCN-` and `LEDGER-` ids are tool-level observations with no spec row. [`docs/DESIGN.md`](docs/DESIGN.md) explains the model and the decisions taken where the spec is silent.

## Run against real servers

| Target | probe | pay | scenarios |
|---|---|---|---|
| Upstream example server `examples/typescript/servers/express` with the published SDK 2.26.0, facilitator `x402.org` for `pay`, the tool's doubles otherwise (2026-09-21) | 16 pass, 1 warn (malformed headers get 402, not 400), 1 not attributable (the scripted facilitator accepts a zero signature) | 9 pass, 2 skipped (spendable negatives), one settled payment | 11 pass, 3 skipped (no witness: the example serves its own handler) |
| Otoroshi master (18.0.0-dev, commit `320f1417`) with the standalone `otoroshi-x402` plugin (commit `f1e5c3b`) loaded as a JAR; `site2md.cleverapps.io` with facilitator `x402.org` for `probe` and `pay` (`docs/runs/otoroshi-master-site2md-all.json`), a local instance wired to the tool's doubles for `scenarios` (`docs/runs/otoroshi-master-local-*.json`), all on 2026-09-22 | 21 pass, 0 warn (the version 1 payload is reported, PROBE-V1) | 12 pass, one settled payment read back on chain: transaction sealed, one transfer of the amount from the payer to `payTo`, the tool's nonce recorded as used by the USDC contract | 15 pass, 1 skipped (`payment-identifier` not required), witness wired: verify before the backend, settle after it, rejected, pending, unreadable and failing-backend outcomes relayed as the spec asks, sidechannel never forwarded, replay answered with the original receipt. The same 15 pass with `--mechanism svm` on the route's Solana devnet offer; `probe` finds the Solana offer well formed (fee payer from the facilitator, base58 keys) |

Both implementations make the same defensible choice the spec leaves open (402 with a fresh challenge for a malformed header); neither fails a required check in any executed suite. Each row names the artefact behind its figures; the reference server run predates the chain reading and the Solana checks, so its `pay` and `probe` columns have no ledger or Solana lines. The local Otoroshi run starts an Otoroshi with the plugin, creates a route whose backend is the tool's witness and whose facilitator is the scripted one (`serve` keeps both up while the route is created), then runs `probe` and `scenarios` for each offer family.

## What is in the workspace

| Crate | Role | Reusable on its own |
|---|---|---|
| `x402-checker-types` | wire types of v2, header names, tolerant base64 codec, CAIP-2, standard error codes; no I/O | yes, by any Rust x402 client or server |
| `x402-checker-evm` | `exact` on EVM: EIP-3009 authorizations signed with EIP-712, signer recovery; no network | yes |
| `x402-checker-testbed` | a scripted facilitator (EVM and Solana kinds, fee payer advertised) and a witness backend that record every call, with start and end times | yes, as test doubles |
| `x402-checker-ledger` | JSON-RPC reader of a transaction receipt, ERC-20 `Transfer` and EIP-3009 `AuthorizationUsed` decoding, public nodes of the test networks | yes, by anything that checks an EVM settlement |
| `x402-checker` | the checks, the suites, the report and the command line | the tool |

## Building and checking

Rust 1.98 or later, edition 2024. Release binaries for macOS, Linux and Windows are attached to each [GitHub release](https://github.com/davlgd/x402-checker/releases); building from source:

```sh
cargo build --release          # optimised binary in target/release/x402-checker
cargo test --workspace         # the minimum
cargo fmt --all --check        # what CI also runs; nextest and deny need `cargo install cargo-nextest cargo-deny`
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo deny check
```

The test suite needs no network access beyond loopback: it runs the suites against a small resource server written from the spec (`crates/x402-checker/tests/reference_server.rs`), wired to the crate's own doubles, and against a deliberately wrong server that the suites must catch.

## Limits, stated

- Only `exact` with `eip3009` on `eip155` networks is paid for real. `exact` on `solana` networks is inspected and driven through the scripted facilitator, never paid; `permit2`, `erc7710`, `upto`, `batch-settlement`, other networks, MCP and A2A transports are out of scope and reported as such.
- Before sharing a report, know what it keeps. Eight header names are redacted in the recorded exchanges and in the doubles' traces (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Api-Key`, `X-Secret-Key`, `X-Auth-Token`; a Bearer JWT keeps only its algorithm, key id, issuer, `uris` and validity). Everything else is kept as observed: URLs with their query strings, request and response bodies up to the cap, every other header, and the x402 headers whole, `PAYMENT-SIGNATURE` included, since they are what the checks read. A payment authorization is spent once and expires, but it names the payer and the amount; a token or a secret placed anywhere else than in those eight headers is not redacted.
- How a server authenticates to its facilitator is outside the protocol: `scenarios` reports what it saw on the scripted facilitator (a Bearer JWT is summarised, not verified) and judges nothing.
- `pay` refuses networks it does not know as testnets unless `--allow-mainnet` is given, and sends the spendable negative authorizations (wrong amount, wrong recipient) only with `--spendable-negatives`.
- After the payment the chain is read through one JSON-RPC node (a public node of the test network, or `--rpc-url`): the transaction must be included and successful, carry exactly one `Transfer` of the amount from the payer to `payTo` emitted by the asset, and the asset must have recorded the tool's nonce as used. That is a sealed block as one node reports it, not finality, not a balance, not a cryptographic proof; a sequencer preconfirmation (receipt with a zero block hash) is waited out and, if still there at the deadline, reported as not assessable. When the chain contradicts the receipt the server is not blamed alone, since it relays its facilitator's word: the finding is blocked, not failed. The receipt read, logs included, is kept in the JSON report as a `ledger` snapshot. `--no-ledger` leaves these checks explicitly undemonstrated.
- Sequence claims (verify before the resource, settle after it, no settle when the resource fails) are made only when the witness backend is in the loop; otherwise they are skipped, not guessed.
- The spec leaves points open (base64 variant, 400 versus 402 for a malformed header, empty `accepts`, the answer to a pending settlement beyond the receipt). The tool names its reading in the finding rather than presenting it as the spec's.

## License

Apache License 2.0, copyright 2026 davlgd. The specification texts under `spec/` are copies from the x402 Foundation repository, pinned at the commit named in `spec/UPSTREAM_COMMIT`.
