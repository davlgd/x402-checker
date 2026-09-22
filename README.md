# x402-checker

Checks an [x402](https://github.com/x402-foundation/x402) v2 resource server against the specification, and says how far it conforms.

Each finding names the requirement it measures, or the policy it states, and quotes the clause behind it. A failure can be argued against the specification text, not against the tool's opinion. The tool was written from the spec alone: a pinned copy lives in `spec/`, and its commit is stamped in every report.

## Install

With [mise](https://mise.jdx.dev), the GitHub backend fetches the release binary for your platform and puts it on your `PATH`:

```sh
mise use -g github:davlgd/x402-checker@0.1.0
```

The same binaries can be downloaded from the [releases page](https://github.com/davlgd/x402-checker/releases), each with its SHA-256, for macOS, Linux and Windows. The crates are not on crates.io yet; to build from source, with Rust 1.98 or later:

```sh
cargo install --locked --git https://github.com/davlgd/x402-checker x402-checker
```

## Usage

The simplest run needs nothing but the URL of a paid resource. It reads the `402` and its terms, sends malformed payment headers, and tries a payment that cannot be valid.

```sh
x402-checker probe https://api.example.com/premium
```

With a funded test wallet, the tool pays once, for real, through the server's own facilitator. It then reads the chain to confirm the transfer, replays the payment, and sends authorizations the server must refuse. The key is read from the environment; type it without echo so that it stays out of your shell history.

```sh
read -rs X402_PAYER_KEY && export X402_PAYER_KEY
x402-checker pay https://api.example.com/premium --max-amount 100000
```

The deepest run hosts a scripted facilitator and, when asked, a witness backend, then waits for you to point the server at them. It drives every settlement outcome through the server: valid, invalid, rejected, pending, unreadable, failing resource, replay. With the witness as the server's upstream, it also checks the order of the server's calls. Here the server runs on the same machine and reaches both doubles on the loopback addresses printed at start; a server elsewhere needs the two listeners on addresses it can reach.

```sh
x402-checker scenarios http://paid.oto.tools:8080/premium --witness-listen 127.0.0.1:4021 --pause
```

`all` combines `probe` and `pay`. `ledger` checks a past settlement on chain from its transaction hash and the expected payment details, without paying again; it is always strict. `serve` hosts the two doubles for a manual session.

Requests can carry the method, headers and body the resource expects, with `-X`, `-H` and `-d`. Add `--format json -o report.json` for a machine-readable report, and `--strict` to fail a CI job when the executed scope left required checks undemonstrated.

## Reading a report

Each line is one check, with its verdict, requirement id, title and level.

```
  PASS HTTP-001     an unpaid request is answered with status 402  (required)
  WARN HTTP-010s    a malformed PAYMENT-SIGNATURE is answered with status 400  (recommended)
       not base64 -> 402; base64 of plain text -> 402
       spec: transports-v2/http.md, Error Handling: "Invalid Payment | 400 | Malformed payment payload or requirements"
       note: the same table maps Payment Failed to 402, so a 402 with a fresh challenge is defensible
```

A `required` check comes from a MUST, a required field or prescriptive prose: failing it means not conformant. A `recommended` check comes from a SHOULD, or from a policy the tool names as such: failing it is a warning. An `optional` check comes from a MAY or an example: it only informs.

A failure names who is responsible. Only failures attributed to the server count against conformance. A failure caused by a real facilitator, a node or the tool itself is shown as `BLOCK` and listed as not demonstrated. `SKIP` means a precondition on the tool's side was missing, such as a payer key. `N/A` means the check could not be assessed on this server, for instance a Solana check on a server that offers no Solana payment.

The exit code is `0` when no required check failed in the executed scope, `1` when one did, and `2` when nothing could be graded. With `--strict`, required checks left undemonstrated also give `2`: the run is incomplete, which is not a verdict against the server, and a payment family the server does not offer is enough to make it so.

Ids such as `CORE-002` or `HTTP-003` point at rows of [`docs/requirements.md`](docs/requirements.md); ids prefixed `PAY-`, `PROBE-`, `SCN-` or `LEDGER-` are observations of the tool with no spec row. [`docs/DESIGN.md`](docs/DESIGN.md) explains the model and the decisions taken where the spec is silent.

## What it covers

Payments are made with the `exact` scheme on EVM networks, through EIP-3009 authorizations: that is the only mechanism the tool holds a key for. `pay` refuses networks it does not know as testnets unless `--allow-mainnet` is given.

Offers of `exact` on Solana are inspected by `probe`, and `scenarios --mechanism svm` runs the same scenarios through them with random bytes standing for the transaction, since the scripted facilitator reads none. That exercises the server's Solana path, not a wallet: a server that parses the transaction and refuses those bytes is reported as not assessable, never as non-conformant. Solana offers are never paid.

After a payment, one JSON-RPC node is asked for the receipt. The transaction must be included and successful, carry exactly one matching transfer of the offered asset from the payer to the recipient, incidental transfers allowed, and the asset must have recorded the expected authorization as used: the nonce the tool chose in `pay`, the one you give to `ledger`. That is a sealed block as one node reports it, not finality. When the chain contradicts the receipt, the server is not blamed alone, since it relays its facilitator's word.

Claims about the order of calls are made only when the witness backend is in the loop. Everything else, such as `upto`, `permit2`, other networks and the MCP transport, is reported as out of scope, never as a failure.

## Tested against

The upstream example server (`examples/typescript/servers/express`, SDK 2.26.0) and an Otoroshi gateway running the `otoroshi-x402` plugin were both run through the suites. No required check attributed to either server failed. The Otoroshi payment was also read back on chain; the reference server runs predate the ledger checks and, with no witness in the loop, leave the order of calls unassessed. The reports are in [`docs/runs/`](docs/runs/).

On one point the spec leaves open, the answer to a malformed payment header, the two differ in those captures: the reference server answers `402` with a fresh challenge, which the tool reports as a warning, and Otoroshi answers `400`.

## Sharing a report

A report contains what the tool observed: URLs, headers, bodies up to a cap, and the receipts. Eight credential headers are redacted: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Api-Key`, `X-Secret-Key` and `X-Auth-Token`. A Bearer JWT keeps only its algorithm, key id, issuer, `uris` and validity.

The x402 headers are kept whole, since they are what the checks read. A secret placed anywhere else is not redacted.

## Workspace

The repository is a Cargo workspace of five crates. Four of them carry no opinion about conformance and can be reused on their own.

| Crate | Role |
|---|---|
| `x402-checker-types` | Wire types of v2, header names, base64 codec, CAIP-2 and base58 helpers |
| `x402-checker-evm` | EIP-3009 authorizations signed with EIP-712, signer recovery |
| `x402-checker-testbed` | Scripted facilitator and witness backend that record every call |
| `x402-checker-ledger` | JSON-RPC receipt reader, `Transfer` and `AuthorizationUsed` decoding |
| `x402-checker` | The checks, the suites, the report and the command line |

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The tests need no network access beyond loopback. They run the suites against a small resource server written from the spec, wired to the workspace's own doubles.

## License

Apache License 2.0, copyright 2026 davlgd. The specification texts under `spec/` are copies from the x402 Foundation repository, pinned at the commit named in `spec/UPSTREAM_COMMIT`.
