# x402-checker: design

A command-line tool that tells whether an x402 v2 **resource server** conforms to the specification, and how far. It is written from the spec text (`spec/`, upstream commit `59f1347a`) and from nothing else, plus the external bases the spec relies on and names: the EIP-3009 text pinned in `spec/external/`, and the CAIP-2 and Solana address formats the checks cite where they apply them. Requirement ids in the code (`CORE-002`, `HTTP-003`, `EVM-012`, ...) point at rows of `docs/requirements.md`, so every verdict can be argued against a clause. A letter suffix (`CORE-005e`, `HTTP-010s`) marks a check derived from that row that measures one aspect of it; ids prefixed `PAY-`, `PROBE-`, `SCN-` or `LEDGER-` are tool-level observations with no spec row, and their source is `policy`. The EIP-3009 text a check cites (for its `AuthorizationUsed` event) is pinned in `spec/external/`.

## What it judges, what it does not

Judged: an HTTP resource server speaking x402 v2 with the `exact` scheme. On an EVM network (`eip155:*`, EIP-3009 authorization) the tool builds and pays real payments; that is the only mechanism it holds a key for. On Solana (`solana:*`) it inspects the offers (`probe`) and drives the server's path through its scripted facilitator (`scenarios --mechanism svm`), with random bytes standing for the transaction, and never pays. Everything else is reported as **cannot assess**, not as a failure: a server that only offers v1, other networks, or schemes the tool cannot pay.

Not judged: facilitators as such (the tool hosts one to exercise the server), clients, MCP and A2A transports, mainnet behaviour (the tool refuses a mainnet CAIP-2 unless `--allow-mainnet` is given), performance.

## Levels, sources and verdicts

Every check declares a **level** and a **source**. The level says what a failure means; the source says how strong the textual basis is, so that a reader can weigh the verdict.

| Level | Spec wording | Effect on the outcome |
|---|---|---|
| `required` | MUST, MUST NOT, "Required" column of a field table, prescriptive prose | a failure makes the target **not conformant** |
| `recommended` | SHOULD, SHOULD NOT, and a few operational policies the tool names as such | a failure is reported as a **warning**, never fatal |
| `optional` | MAY, examples, choices the spec leaves open | never a failure, never a warning: **information** only, since a MAY commands nothing and an example has no force |

Verdicts: `pass`, `fail`, `warn`, `info`, `skip` (a precondition on the tool's side was missing), `cannot-assess` (the target is outside what the check can judge). A `fail` carries an **attribution**: `target`, `dependency` (a real facilitator, an RPC node, a wallet balance), `harness` (the tool) or `unknown` (the observation does not tell who is responsible; the text output prints it as `BLOCK`). Only target failures count against conformance; the others are listed as not demonstrated.

| Source | Meaning |
|---|---|
| `explicit-must` | an RFC 2119 keyword in the text |
| `field-table` | the Required/Optional column of a schema table |
| `prose` | prescriptive prose without a keyword ("the server responds with", "is") |
| `example` | only shown by example |

A check may also carry an **ambiguity** note when the spec is silent or contradictory on the point measured; the note is printed with the verdict so that nobody mistakes the tool's reading for the spec's.

Every check produces one **verdict**:

| Verdict | Meaning |
|---|---|
| `pass` | observed behaviour satisfies the clause |
| `fail` | observed behaviour contradicts the clause (evidence attached) |
| `warn` | a `recommended` clause is not followed |
| `info` | an `optional` clause: what was observed, with no judgement |
| `skip` | precondition not met on our side (no payer key, no facilitator scenario, no witness); the check was not run |
| `cannot-assess` | the target is outside what the check can judge (v1 only, non-EVM only, credential wall) |

A `fail` also names **who is responsible**: `target` (the server under test), `dependency` (a real facilitator, an RPC node, a clock or a wallet balance the tool depends on) or `harness` (the tool itself). Only `target` failures count against conformance; the others are reported so the run can be fixed and repeated.

## Scope and exit codes

A run never certifies more than it exercised. The report states the **scope** (the suites run: `probe`, `pay`, `scenarios`, `ledger`) and lists the `required` checks that were **not exercised** in that scope; `probe` alone never certifies a payment or a call order, and the text says so. Exit codes: `0` no `required` check failed in the executed scope, `1` at least one `required` check failed, `2` nothing could be graded. With `--strict`, unexercised `required` checks make the outcome `incomplete` (exit code 2, not a verdict against the server), for CI jobs that demand the full scope. The JSON report carries `scope`, `incomplete` (the unexercised required ids) and `outcome`.

## Suites and modes

The tool grows in three rings; each ring needs more from the operator.

### 1. `probe`: no funds, no cooperation

Plain HTTP against the target URL. Checks the 402 signal, the `PAYMENT-REQUIRED` header (decoding, base64 variant, `PaymentRequired` schema, `ResourceInfo` bounds, `accepts[]` fields, CAIP-2, reserved `extra` keys, extension `info`/`schema` structure), the HTTP error mapping for malformed `PAYMENT-SIGNATURE` values (not base64, base64 of non-JSON, missing fields, wrong version, `accepted` matching no offer, unknown scheme, structurally valid payload with a 65-zero-byte signature so that nothing can settle), and, when the `bazaar` extension is advertised, its declared shape. Also records informational facts: body content type, CORS exposure of the three headers, response time.

### 2. `pay`: one testnet payment, the server's own facilitator

Given a payer key (`--payer-key` or `X402_PAYER_KEY`), the tool builds a real `exact` EVM payment for one of the offered `accepts[]` entries (testnet only), sends it, and checks the success path (200, `PAYMENT-RESPONSE`, receipt fields, `network` equals the accepted network, non-empty transaction), then the negative paths that a real facilitator will refuse: same header replayed (must not settle twice: no second success receipt with a new transaction), expired `validBefore`, `value` different from `amount`, `to` different from `payTo`. When `payment-identifier` is advertised, the identifier round trip is checked too. The receipt of the honest payment is then read on chain (`suites/ledger.rs`, crate `x402-checker-ledger`): the transaction is included and successful on the paid network, it carries exactly one `Transfer` of `amount` of `asset` from the payer to `payTo`, and the asset emitted `AuthorizationUsed(payer, nonce)` for the nonce the tool chose, which binds the transfer to this payment rather than to any payment of the same amount. The same checks run standalone on an earlier receipt with `x402-checker ledger`.

### 3. `scenarios`: the tool hosts the facilitator (and a witness backend)

The operator points the server under test at the tool's scripted facilitator (`/supported`, `/verify`, `/settle`) and, when possible, at its witness backend. Each scenario scripts the facilitator's answers and observes what the server does: request bodies of `/verify` and `/settle` (`x402Version`, payload echo, requirements echo), order of calls around the backend call, no settle when the backend fails, the number of settle calls (reported, not judged: D7), `EXTENSION-RESPONSES` never forwarded (header, body and receipt searched for a marker), settle rejected (402 relaying the facilitator's `success: false`, reason and transaction), settle pending (receipt with the hash, no claim of success; the absence of a fresh challenge is a `recommended` policy: D9), unreadable settle (no claim of success), verify invalid (no settle, resource not executed, reason surfaced), replay of a settled payment (the facilitator keeps the consumed nonce and would answer a distinct hash, so a new success cannot pass for a cached receipt). Every scenario first establishes that its scripted outcome was met; otherwise its checks are reported as not demonstrated. The witness backend is optional; without it, sequence checks that need it are `skip`ped with the reason, and a witness that is started but never called is reported as not wired.

The facilitator and the witness can also run standalone (`x402-checker serve`) for manual sessions.

## Workspace

```
x402-checker/
  Cargo.toml              workspace, shared deps, lints, release profile
  crates/
    x402-checker-types/           wire types of v2, header names, base64 codec, CAIP-2, error codes. No I/O.
    x402-checker-evm/             exact EVM payments: EIP-3009 authorization, EIP-712 signing, nonce, address checks.
    x402-checker-testbed/         scripted facilitator + witness backend (axum), call recording, scenario scripts.
    x402-checker-ledger/          JSON-RPC receipt reader, Transfer and AuthorizationUsed decoding, public test-network nodes.
    x402-checker/     the tool: check model, suites, evidence, report (text, JSON), CLI.
  docs/                   requirements, design, decisions
  spec/                   pinned copy of the upstream spec files used
```

Why five crates: `x402-checker-types` and `x402-checker-evm` are reusable by any Rust x402 client or server and carry no opinion; `x402-checker-testbed` is reusable as a test double in other projects' integration tests; `x402-checker-ledger` is reusable by anything that has to confirm an EVM settlement and knows nothing about x402 beyond the two events; the tool is the only crate that knows about checks. No more splitting: the check model, the suites and the report form one library crate, which the binary drives; the library is usable on its own (the tests do), a separate crate for the CLI would only move `main.rs`.

## Traceability

The report carries the tool version, the upstream commit of the spec copy it was built against (`spec/UPSTREAM_COMMIT`), the scope, the suites omitted with their reason, the list of required checks not demonstrated, every HTTP exchange and, for `scenarios`, the trace of the doubles' calls. The text says "conformant within the executed scope": a run shows what it observed, nothing more.

## Core model (crate `x402-checker`)

```rust
pub struct Check { id: &'static str, title: &'static str, level: Level, source: Source, clause: &'static str, ambiguity: Option<&'static str> }
pub enum Verdict { Pass, Fail, Warn, Info, Skip, CannotAssess }
pub enum Attribution { Target, Dependency, Harness, Unknown }
pub struct Finding { check: Check, verdict: Verdict, detail: String, evidence: Vec<usize>, attribution: Option<Attribution> }
pub struct SuiteResult { name: &'static str, findings: Vec<Finding>, traces: Vec<Trace>, ledger: Vec<LedgerSnapshot> }
pub struct Report { tool, spec_commit, eip3009_commit, target, started_at, finished_at, scope, omitted, strict, suites, exchanges, summary, outcome, exit_code }
```

A suite is a module with an `async fn run(ctx: &mut Context, options) -> SuiteResult`, where `Context` holds the target, the options and the recording HTTP client (`http::Client`, every exchange kept with its decoded x402 headers). Checks are declared once, as constants next to the code that evaluates them; the requirement id is the link to `docs/requirements.md`. No trait hierarchy: findings are data, the report assembles them.

Evidence: a finding references exchanges by index; the JSON report includes them all (bodies capped at 8 KiB), the doubles' call traces and the ledger snapshots; the text report prints the exchanges a failure points at, everything under `--verbose`.

## Output

Text (default): one block per suite, one line per check (`PASS`/`FAIL`/`WARN`/`SKIP`/`N/A`, id, title, clause), failures expanded with the observed value and the clause quote, a final summary line and the exit code meaning. Colour when stdout is a terminal, plain otherwise (`--color auto|always|never`).

JSON (`--format json`): the `Report` above, stable field names, `schema_version` field, suitable for CI artefacts and diffing between runs.

## Command line

```
x402-checker probe <URL> [-X METHOD] [-H 'Name: value']... [-d BODY]
x402-checker pay   <URL> [--payer-key 0x… | env X402_PAYER_KEY] [--allow-mainnet] [--max-amount N] [--spendable-negatives] [--rpc-url URL | env X402_RPC_URL] [--ledger-wait S] [--no-ledger]
x402-checker ledger <TX_HASH> --asset A --pay-to A --amount N --payer A [--nonce H] [--network CAIP-2] [--rpc-url URL]   an earlier settlement, read on chain
x402-checker scenarios <URL> [--facilitator-listen 127.0.0.1:4020] [--facilitator-public-url http://…] [--witness-listen …] [--witness-public-url …] [--pause] [--settle-wait S] [--network CAIP-2]... [--mechanism evm|svm] [--facilitator-fee-payer BASE58]
x402-checker serve [--facilitator-listen …] [--witness-listen …] [--network CAIP-2]   standalone doubles
x402-checker all <URL> ...                                          probe, then pay when a key is given; suites not run are listed in the report
common: --format text|json, --output <file>, --timeout <s>, --strict, --verbose, --color
```

Defaults are safe: no funds are needed for `probe`; `pay` refuses mainnet; keys are read from the environment rather than shell history when possible; the tool never prints a private key.

## Dependencies (latest at the time of writing)

`clap` 4.6 (CLI, derive), `tokio` 1.53, `reqwest` 0.13 (rustls, no system TLS), `serde`/`serde_json`, `base64` 0.23, `alloy-primitives` 1.7 + `alloy-sol-types` 1.7 + `alloy-signer-local` 2.4 (EIP-712 typed data and secp256k1 signing), `axum` 0.8 (testbed, and the reference server of the tests), `jsonschema` 0.56 (an extension's `info` against its own `schema`), `thiserror` 2, `anyhow` (binary only), `url`, `jiff` 0.2 (timestamps), `rand` 0.10 (nonces), `owo-colors` 4 (terminal colour), `tracing` (testbed logs). Tests: `assert_cmd` + `predicates` for the command line; the suites are exercised against the reference server of `tests/reference_server.rs` and the crate's own doubles, not against mocks.

## Quality gates

Edition 2024, MSRV = current stable. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` with `clippy::pedantic` enabled in the workspace lints (allow-listed exceptions documented inline), `cargo nextest`, `cargo deny check` (licences, advisories), `cargo outdated` before each release. Release profile: `lto = "fat"`, `codegen-units = 1`, `strip = true`, `panic = "abort"`, `opt-level = 3`. CI workflow runs the same commands.

## Decisions log

- D1. Verdict `cannot-assess` and exit code 2 exist so that an honest non-EVM or v1 server is never called non-conformant.
- D2. Base64 is decoded leniently (standard or URL-safe, padded or not) because the transport spec never names the variant; the variant found is reported.
- D3. A 402 answer to a malformed `PAYMENT-SIGNATURE` is a warning, not a failure: the HTTP transport maps both "Invalid Payment" (400) and "Payment Failed" (402); a 200 or 500 is a failure.
- D4. Replay is judged on "not settled twice", the only thing the spec requires, not on a particular status code.
- D5. Sequence claims (verify before backend, settle after backend, no settle on backend failure) are only asserted when the witness backend is in the loop; without it they are skipped, not guessed.
- D6. The tool's own client behaviour follows the client-side MUSTs (echo extension `info`, prefer `authorization`, never build a payment for an unknown flow), so that no failure can be blamed on a non-conformant client. One stated exception: under `scenarios --mechanism svm` the transaction is random bytes, not a signed Solana transaction; a server that parses it and refuses is reported as not assessable, never as failing (D13). Failures caused by a dependency (RPC, real facilitator, clock, balance) or by the tool are still reported, attributed as such, and kept out of the conformance outcome.
- D7. The number of `/settle` calls is reported as a fact, never judged: the core spec allows several settles per payment and a transport may retry. The required oracle is "at most one effective transfer for the selected method": in `pay` mode one success receipt with a transaction, in `scenarios` mode no second success once the scripted facilitator has consumed the nonce.
- D8. A replayed `PAYMENT-SIGNATURE` is judged on "no second successful settlement" only. Delivering the cached resource again is allowed (the payment identifier extension relies on it) and is reported as information.
- D9. For `settlement_pending` the required oracle is the receipt: non-terminal, with `transaction` and `network` preserved. "No fresh challenge inviting a second signature" is a `recommended` check explicitly labelled as an operational policy.
- D10. For a rejected settlement the oracle is faithful relay of the facilitator's `SettleResponse`, including an empty `transaction` only when the facilitator sent one; there is no general rule that a rejection has no transaction.
- D11. Section 8 of the core spec: only the table 8.3 fields are `required`; the list envelope comes from an example and is `optional`; Bazaar discovery endpoints are MAY and their absence never fails a resource server.
- D12. The chain is read after the honest payment, from one JSON-RPC node, on the network of the paid offer (a receipt naming another network is an inconsistency reported before any node is contacted, never a reason to look elsewhere). Three separate claims: included and successful; exactly one `Transfer(payer, payTo, amount)` from the asset, incidental transfers allowed, several identical ones not decidable; `AuthorizationUsed(payer, nonce)` from the asset in the same transaction, for the nonce expected (the one the tool chose in `pay`, the one the operator gives to `ledger`). The third claim is two events observed in one transaction, no more: it says the asset consumed that authorization there, not that the transfer is cryptographically caused by it. A chain that contradicts the receipt is attributed `unknown` (the server relays its facilitator; the ledger alone does not tell who named the transaction), an unreachable or malformed node is a dependency, a node of another chain is a tool misconfiguration. Judged on the receipt's logs, never on balances, `tx.to` (a relay may call the token) or the total number of logs; a sealed block as one node reports it, finality not claimed. A receipt with a zero block hash is a sequencer preconfirmation (Flashblocks-style caches answer one before the block exists): the wait goes on for a sealed one and, at the deadline, the three claims are not assessable rather than passed. A node that answers `null` until the deadline returned no inclusion receipt, whether the transaction is pending, dropped or unknown to it (attributed `unknown`); a node whose answer never completes has not been observed (a dependency); a status other than 0 or 1 is a shape error, not a revert. The receipt the findings were judged on (chain id, state, block, status, logs with their index, node, instant) is kept in the report as a `ledger` snapshot of the suite, so that the reading can be re-examined later without trusting the prose.
- D13. Solana (`exact` on `solana:*`): the tool holds no Solana key and reads no Solana ledger. `probe` judges the offer against `scheme_exact_svm.md` (fee payer, base58 keys, hints); `scenarios --mechanism svm` sends random bytes as the transaction, which the scripted facilitator accepts and dedups by the decoded bytes, so that the server's Solana path (offer, relay, order, outcomes, replay) is exercised without a wallet; `pay` skips Solana offers. The double follows the scheme's example, which shows the fee payer as the receipt's `payer` (an example, not a rule: SVM-008).
- D14. Facilitator authentication is not in the protocol: `scenarios` reports what the server sent to the scripted facilitator (`SCN-FACILITATOR-AUTH`, a Bearer JWT summarised by algorithm, key id, `uris` and lifetime) as information, never as a verdict.
