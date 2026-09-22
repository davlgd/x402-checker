# x402 v2 requirements, independent extraction (core specification and HTTP transport)

Source: `spec/x402-specification-v2.md` and `spec/transports-v2_http.md`, upstream commit `59f1347a`. Scheme and extension files are covered in `requirements-claude-part2.md`. Written from the spec text only; no implementation was consulted.

Legend. Role: RS = resource server, C = client, F = facilitator, ANY. Level: the RFC 2119 keyword the text uses; `MUST(implicit)` when the text is prescriptive without a keyword ("Required" column of a field table, "is", "always"); `EXAMPLE` when the text only shows an example. Testability for a resource server, black box: `probe` = no funds, a plain HTTP client; `paid` = one real testnet payment; `facilitator` = only if the tool hosts the facilitator the server under test talks to; `n/a` = not observable from outside.

## Core specification

### Types, section 5

| ID | Role | Level | Clause | Requirement | Testable |
|---|---|---|---|---|---|
| CORE-5.1-01 | RS | MUST(implicit) | 5.1.1 "responds with a payment required signal containing the PaymentRequired object" | When payment is required, the response carries a `PaymentRequired` object at the transport's canonical location (HTTP: `PAYMENT-REQUIRED` header). | probe |
| CORE-5.1-02 | RS | MUST(implicit) | 5.1.2 table, `x402Version` Required, "must be 2" | `PaymentRequired.x402Version` is present, a number, equal to 2. | probe |
| CORE-5.1-03 | RS | MAY | 5.1.2 `error` Optional | `error` may be present; when present it is a string. | probe |
| CORE-5.1-04 | RS | MUST(implicit) | 5.1.2 `resource` Required | `resource` is present and is a `ResourceInfo` object. | probe |
| CORE-5.1-05 | RS | MUST(implicit) | 5.1.2 `accepts` Required, "array of payment requirement objects" | `accepts` is present and an array of `PaymentRequirements`. The spec does not say it must be non-empty; an empty array is a gap (see ambiguities). | probe |
| CORE-5.1-06 | RS | MAY | 5.1.2 `extensions` Optional | `extensions` may be present; when present it is an object. | probe |
| CORE-5.1-07 | RS | MUST(implicit) | 5.1.2 PaymentRequirements table | Each `accepts[]` entry has `scheme` (string), `network` (string), `amount` (string), `asset` (string), `payTo` (string), `maxTimeoutSeconds` (number); `extra` optional object. | probe |
| CORE-5.1-08 | RS | MUST(implicit) | 5.1.2 `network` "CAIP-2 format", 11.1 `{namespace}:{reference}` | `network` follows CAIP-2 `namespace:reference`. | probe |
| CORE-5.1-09 | RS | MUST(implicit) | 5.1.2 `amount` "in atomic token units", type string | `amount` is a string holding an integer count of atomic units (the spec gives no grammar; a non-negative decimal integer is the only reading consistent with the examples). | probe |
| CORE-5.1-10 | RS | MUST(implicit) | 5.1.2 `asset` "Token contract address or ISO 4217 currency code" | `asset` is a token address for blockchain networks or an ISO 4217 code for fiat. Format per network is scheme-defined. | probe (format check per scheme) |
| CORE-5.1-11 | RS | MUST(implicit) | 5.1.2 `payTo` "Recipient wallet address or role constant" | `payTo` is an address or a role constant such as "merchant". | probe |
| CORE-5.1-12 | RS | MUST(implicit) | 5.1.2 `maxTimeoutSeconds` "Maximum time allowed for payment completion", number | `maxTimeoutSeconds` is a number. Semantics beyond that are unspecified. | probe |
| CORE-5.1-13 | RS | MUST(implicit) | 5.1.2 `extra` "Reserved protocol keys: assetTransferMethod, paymentFlow" | If `extra.assetTransferMethod` or `extra.paymentFlow` are present, they carry the section 6.1 meaning, not scheme-private data. | probe |
| CORE-5.1-14 | RS | MUST(implicit) | 5.1.2 ResourceInfo `url` Required | `resource.url` is present, a string, the URL of the protected resource. | probe |
| CORE-5.1-15 | RS | MAY | 5.1.2 ResourceInfo optional fields | `description`, `mimeType` strings when present. | probe |
| CORE-5.1-16 | RS | MUST(implicit) | 5.1.2 `serviceName` "Printable ASCII, max 32 characters" | When present, `serviceName` is printable ASCII, at most 32 characters. | probe |
| CORE-5.1-17 | RS | MUST(implicit) | 5.1.2 `tags` "Max 5 entries; each printable ASCII, max 32 characters" | When present, `tags` has at most 5 strings, each printable ASCII of at most 32 characters. | probe |
| CORE-5.1-18 | RS | MUST(implicit) | 5.1.2 `iconUrl` "Absolute https/http URL ... Max 2048 characters" | When present, `iconUrl` is an absolute http(s) URL of at most 2048 characters. | probe |
| CORE-5.1-19 | RS | MUST(implicit) | 5.1.2 Extensions table, `info` and `schema` Required | Each value of `extensions` is an object with `info` (object) and `schema` (object, a JSON Schema describing `info`). | probe |
| CORE-5.1-20 | RS | MUST(implicit) | 5.1.2 "Servers advertise supported extensions in PaymentRequired" | Extensions a server supports are advertised in `PaymentRequired.extensions`. | probe |
| CORE-5.1-21 | C | MUST | 5.1.2 "The client must include at least the info received; it may append ... cannot delete or overwrite" | Clients echo extension `info` in `PaymentPayload.extensions` without deleting or overwriting server-provided keys. Server-side observable only as a rejection policy, which the spec does not define. | n/a (client rule); the tool must itself comply when it acts as client |
| CORE-5.2-01 | C | MUST(implicit) | 5.2.2 table | `PaymentPayload` has `x402Version` (number), `accepted` (PaymentRequirements object), `payload` (object); `resource` and `extensions` optional. | tool behaviour; RS side: probe with malformed payloads, see CORE-9 |
| CORE-5.2-02 | RS | MUST(implicit) | 5.2.2 "`accepted` ... indicating the payment method chosen" | The server relates `accepted` to one of its offered `accepts[]` entries. The spec does not say how strictly (equality, subset); a gap. | paid, facilitator (send `accepted` not matching any offer, expect a non-success) |
| CORE-5.2-03 | C | MUST(implicit) | 5.2.2 exact EVM payload table | For exact EVM, `payload` has `signature` (string) and `authorization` object with `from`, `to`, `value`, `validAfter`, `validBefore`, `nonce`, all strings; nonce is 32 bytes. | tool behaviour |
| CORE-5.3-01 | RS | MUST(implicit) | 5.3.1 "After payment settlement, the server includes transaction details in the payment response field" | After settlement the server returns a `SettlementResponse` at the transport location (HTTP: `PAYMENT-RESPONSE`). | paid, facilitator |
| CORE-5.3-02 | RS/F | MUST(implicit) | 5.3.2 table | `SettleResponse` has `success` (boolean), `transaction` (string), `network` (string, CAIP-2); `errorReason`, `payer`, `amount`, `extensions` optional. | paid, facilitator |
| CORE-5.3-03 | RS/F | MUST(implicit) | 5.3.2 `errorReason` "omitted if successful" | `errorReason` is absent when `success` is true. | paid, facilitator |
| CORE-5.3-04 | RS/F | MUST(implicit) | 5.3.2 `transaction` "empty string if no transaction was broadcast" | When nothing was broadcast, `transaction` is the empty string, not absent. | facilitator (rejected settle) |
| CORE-5.3-05 | RS/F | MUST | 5.3.2 and 9 `settlement_pending` "MUST carry a non-empty transaction ... and network" | A settle response with `errorReason: settlement_pending` has a non-empty `transaction` and a `network`. | facilitator (pending settle passthrough) |
| CORE-5.4-01 | F | MUST(implicit) | 5.4.2 table | `VerifyResponse`: `isValid` boolean required; `invalidReason` optional, omitted if valid; `payer`, `extensions`, `extra` optional. | facilitator side (how the RS consumes it) |
| CORE-5.4-02 | F | MAY | 5.4.2 last paragraph, 7.2.1 | Facilitators may expose `extensionResponses` through a sidechannel that is never serialized to buyers. | facilitator: tool sends `EXTENSION-RESPONSES`, checks the RS never forwards it |

### Payment schemes and flows, section 6

| ID | Role | Level | Clause | Requirement | Testable |
|---|---|---|---|---|---|
| CORE-6.1-01 | RS, C | MUST | 6.1 "clients and servers MUST interpret them as defined here" | `extra.assetTransferMethod` and `extra.paymentFlow` are protocol-reserved keys with the 6.1 meaning. | probe |
| CORE-6.1-02 | RS | MUST | 6.1 "When the resolved payment flow is not authorization, accepts[].extra.paymentFlow MUST be present" | If the offer's flow is `upfront` or `escrow`, `extra.paymentFlow` is present in the offer. | probe (only detectable when the flow is not the default; otherwise vacuous) |
| CORE-6.1-03 | RS | MAY | 6.1 "`authorization` MAY be omitted or explicit" | `extra.paymentFlow: "authorization"` is optional. | probe |
| CORE-6.1-04 | RS | MUST | 6.1 "Resource servers MUST reject unsupported assetTransferMethod / payment flow combinations" | A payload whose `accepted.extra` names an unsupported ATM or flow combination is rejected. | paid or facilitator (craft `accepted.extra.paymentFlow: "escrow"` against an authorization-only offer; expect a non-success) |
| CORE-6.1-05 | C | MUST NOT / SHOULD | 6.1 "Clients MUST NOT construct a payment for a paymentFlow they do not recognize, and SHOULD skip such entries" | Tool behaviour as a client. | n/a |
| CORE-6.1-06 | C | SHOULD | 6.1 "clients SHOULD prefer authorization" | Tool behaviour as a client. | n/a |
| CORE-6.1-07 | RS | MUST(implicit) | 6.1 flow table, `authorization`: "verify → resource → settle → respond" | In the default flow, verify happens before the resource executes and settle after it completes successfully. | facilitator (order of `/verify` and `/settle` calls relative to the backend call; tool hosts both facilitator and, ideally, the backend or observes the response) |
| CORE-6.1-08 | RS | MUST(implicit) | 6.1 `authorization`: "funds move only after it completes successfully" | No `/settle` when the resource execution fails. | facilitator (backend returning an error must yield no settle call) |
| CORE-6.1-09 | RS | MUST | 6.1 "Invariant: at least one check ... MUST run before the resource executes" | The resource never executes with nothing checked. | facilitator (a payload that the facilitator's verify rejects must not reach the backend) |
| CORE-6.1-10 | RS | MUST(implicit) | 6.1 `upfront`/`escrow` rows | For `upfront` and `escrow`, no `/verify`; settle precedes the resource; escrow settles twice. | facilitator, only for servers offering those flows |

### Facilitator interface as consumed by the server, section 7

| ID | Role | Level | Clause | Requirement | Testable |
|---|---|---|---|---|---|
| CORE-7.1-01 | RS | MUST(implicit) | 7.1 request body `{x402Version, paymentPayload, paymentRequirements}` | The server's `/verify` request is JSON with `x402Version: 2`, the client's `paymentPayload` and the server's `paymentRequirements`. | facilitator |
| CORE-7.1-02 | F | MUST NOT | 7.1 "/verify is read-only ... MUST NOT commit payment state" | Facilitator rule; server-side consequence: a server must not treat a verify as a settlement. | facilitator (a verify-only run must not produce a `PAYMENT-RESPONSE` claiming success) |
| CORE-7.1-03 | RS | MUST(implicit) | 7.1 "Resource servers invoke /verify only when the resolved payment flow's ordering includes it" | No `/verify` call for `upfront`/`escrow` offers. | facilitator |
| CORE-7.2-01 | RS | MUST(implicit) | 7.2 "Request: Same structure as /verify" | The `/settle` request has the same structure as `/verify`. | facilitator |
| CORE-7.2-02 | RS | MUST(implicit) | 7.2 note "/settle MAY be invoked more than once for a single payment (for example, the escrow flow)" | Multiple settles only where the scheme defines them; for `exact` authorization a single settle per payment. | facilitator (count settle calls per payment) |
| CORE-7.2-03 | RS | MUST(implicit) | 7.2.1 "not forwarded to buyers" | The `EXTENSION-RESPONSES` header received from the facilitator is never forwarded to the client. | facilitator |
| CORE-7.3-01 | F | MUST(implicit) | 7.3.1 tables | `SupportedResponse`: `kinds` (array of `{x402Version, scheme, network, extra?}`), `extensions` (array), `signers` (object of CAIP-2 patterns to addresses). | facilitator (what the tool must serve so the server accepts it); RS consumption not observable |

### Discovery, section 8

| ID | Role | Level | Clause | Requirement | Testable |
|---|---|---|---|---|---|
| CORE-8-01 | F (Bazaar) | MUST(implicit) | 8.1 response, 8.3 table | `/discovery/resources` returns `{x402Version, items[], pagination{limit, offset, total}}`; each item has `resource`, `type`, `x402Version`, `accepts`, `lastUpdated` (ISO 8601), optional `extensions`. | Bazaar host side; for a resource server, only the advertising half (see BAZAAR rows in part 2) |
| CORE-8-02 | F (Bazaar) | MAY | 8.1 parameters | Filters `type`, `payTo`, `scheme`, `network`, `extensions`, `limit` (1-100, default 20), `offset` (default 0). | Bazaar host side |

### Error handling, section 9

| ID | Role | Level | Clause | Requirement | Testable |
|---|---|---|---|---|---|
| CORE-9-01 | RS/F | MUST(implicit) | 9 "standard error codes that may be returned by facilitators or resource servers" | When a standard condition occurs, the standard code is used: `insufficient_funds`, `invalid_exact_evm_payload_authorization_valid_after`, `..._valid_before`, `..._value_mismatch`, `invalid_exact_evm_payload_signature`, `..._recipient_mismatch`, `invalid_network`, `invalid_payload`, `invalid_payment_requirements`, `invalid_scheme`, `unsupported_scheme`, `invalid_x402_version`, `invalid_transaction_state`, `unexpected_verify_error`, `unexpected_settle_error`, `settlement_pending`. The text says "may be returned", so use of a non-standard code is not a violation; use of a standard code with the wrong meaning is. | probe (malformed payloads: expect a 400 or 402 and, if a reason is given, a fitting one), facilitator (passthrough of `invalidReason`/`errorReason`) |
| CORE-9-02 | F | MAY | 9 `settlement_pending` "Facilitators MAY return this non-terminal code" | The server must accept a pending outcome as non-terminal: not a success, not a definitive failure. | facilitator (pending settle: the server's response must not claim `success: true`, must carry the receipt with the hash, and must not present a fresh challenge as if nothing happened) |

### Security, section 10

| ID | Role | Level | Clause | Requirement | Testable |
|---|---|---|---|---|---|
| CORE-10.1-01 | RS/F | MUST(implicit) | 10.1 "Each authorization includes a unique 32-byte nonce to prevent replay attacks" | A payload replayed with the same nonce is not settled twice. On EVM the contract enforces it; the server is expected not to attempt it. | paid (replay the exact same `PAYMENT-SIGNATURE`; expect no second settlement and no second resource delivery presented as newly paid), facilitator (count settle calls) |
| CORE-10.1-02 | RS/F | MUST(implicit) | 10.1 "Authorizations have explicit valid time windows" | Expired or not-yet-valid authorizations are refused. | paid or facilitator (validBefore in the past: expect refusal with `..._valid_before` when a reason is given) |

## HTTP transport

| ID | Role | Level | Clause | Requirement | Testable |
|---|---|---|---|---|---|
| HTTP-01 | RS | MUST(implicit) | "The server indicates payment is required using the HTTP 402" | Payment required is signalled with status 402. | probe |
| HTTP-02 | RS | MUST(implicit) | "HTTP 402 status code with PAYMENT-REQUIRED header", "canonical HTTP transport location" | The 402 carries a `PAYMENT-REQUIRED` header. Header names are case-insensitive per HTTP; the spec writes them upper case. | probe |
| HTTP-03 | RS | MUST(implicit) | "Base64-encoded PaymentRequired schema in header" | `PAYMENT-REQUIRED` is base64 of the JSON `PaymentRequired`. The example uses the standard alphabet with `=` padding; the spec does not name the variant (gap). | probe (accept standard and URL-safe, padded or not, when decoding; report which variant the server uses) |
| HTTP-04 | C | MUST(implicit) | "Clients send payment data using the PAYMENT-SIGNATURE HTTP header" | The client's `PaymentPayload` travels as base64 JSON in `PAYMENT-SIGNATURE`. | tool behaviour; RS: must read it from that header |
| HTTP-05 | RS | MUST(implicit) | "Servers communicate payment settlement results using the PAYMENT-RESPONSE header" | Settlement results travel as base64 JSON `SettlementResponse` in `PAYMENT-RESPONSE`. | paid, facilitator |
| HTTP-06 | RS | MUST(implicit) | Example (Failure): "HTTP/1.1 402 Payment Required" with `PAYMENT-RESPONSE` `success: false` | A failed settlement is a 402 carrying the failure `SettlementResponse`. | facilitator (rejected settle) |
| HTTP-07 | RS | MUST(implicit) | Header summary table | Exactly these three headers carry protocol data: `PAYMENT-REQUIRED` (S→C), `PAYMENT-SIGNATURE` (C→S), `PAYMENT-RESPONSE` (S→C). | probe, paid |
| HTTP-08 | RS | MUST(implicit) | "Response bodies are a server implementation concern. All x402 protocol information is communicated through headers" | The tool must not require protocol data in bodies; a server may put anything (or nothing) in the 402 body. Body-only signalling without the header is non-conformant (HTTP-02). | probe |
| HTTP-09 | RS | MUST(implicit) | Error handling table | Status mapping: 402 payment required; 400 malformed payment payload or requirements; 402 verification or settlement failed; 500 internal error during payment processing; 200 success. | probe (malformed `PAYMENT-SIGNATURE`: 400 expected; a 402 is arguable since the table also maps "Payment Failed" to 402, see ambiguities), facilitator |
| HTTP-10 | RS | MUST(implicit) | Error table "Success 200: Payment verified and settled successfully" | A paid, settled request answers 200 with `PAYMENT-RESPONSE`. | paid |

## Ambiguities and gaps worth encoding as "optional" or "cannot assess" rather than failures

1. Base64 variant of the three headers is never named; the examples are standard alphabet with padding. Decode leniently, report the variant, never fail on URL-safe or unpadded.
2. `accepts` may be empty as far as the text goes; a 402 with no offer is useless but not prohibited. Report as a warning.
3. How strictly `accepted` must match an offered `accepts[]` entry is undefined (equality, subset, `extra` handling).
4. Malformed `PAYMENT-SIGNATURE`: the HTTP table maps "Invalid Payment" to 400 and "Payment Failed" to 402. A server that answers 402 with a new challenge to a malformed header is defensible. Treat 400 as the expected answer and 402-with-challenge as acceptable-with-note; anything else (200, 500) fails.
5. Whether the 402 after a failed settlement must also carry a fresh `PAYMENT-REQUIRED` is not stated.
6. `maxTimeoutSeconds` semantics ("maximum time allowed for payment completion") are not tied to any observable server behaviour.
7. Header casing: HTTP headers are case-insensitive; the spec's upper case is presentation. Never fail on casing.
8. Replay handling is specified as a security property, not as a status code; the observable requirement is "not settled twice", not a particular status.
9. `settlement_pending` handling by the server is unspecified beyond the receipt content: delivering or withholding the resource are both defensible; presenting a fresh challenge that invites a second signature is the behaviour to flag.
10. Method handling (GET vs POST) of the protected resource is out of scope; the tool needs the method as input.
11. The 402 body: the example shows `{}` with `Content-Type: application/json`; no requirement.
12. Nothing in core or HTTP transport defines a `/.well-known` manifest; tools checking one are checking something outside these two documents.
