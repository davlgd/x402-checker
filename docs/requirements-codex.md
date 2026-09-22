# Independent requirements extraction

Source snapshot: `x402-foundation/x402` commit `59f1347a1a0828af6c9eb9c01298338d3eff3053`, as recorded in `spec/UPSTREAM_COMMIT`. Prepared on 2026-09-21 from the eight local specification files only. No target implementation, previous implementation review, SDK implementation, or Scala test was used as an oracle. This is a requirements inventory, not a conformance result.

## Reading this inventory

Stable IDs identify requirements, not implementation tests. A requirement can need several observations; one observation can support several requirements. Do not renumber an ID when adding checks.

Roles: **RS** resource server; **CL** client (including this tool when it sends requests); **F** facilitator; **V** artifact verifier; **M** mechanism specification author; **D** discovery service. A requirement on F is not automatically a requirement on RS, even when RS delegates to F.

Levels preserve the source's strength:

- **MUST**: explicit uppercase MUST/MUST NOT.
- **MUST (schema)**: a field table says Required/Yes, with the stated type/condition.
- **MUST (prose)**: lowercase must, an imperative algorithm, or a definitive wire contract; this is not silently presented as an uppercase RFC keyword.
- **SHOULD** and **MAY** include lowercase recommendations/permissions, marked where material.
- **Example**: illustrative text, not an independent requirement.

The supplied documents do not establish a universal RFC 2119/8174 interpretation for every lowercase sentence. The distinction above belongs in the machine-readable catalog too. An absent optional capability is not a failure. When a capability is offered, its conditional requirements do apply. Failure to implement a checker is `cannot-assess`, not `skip` or `pass`.

Black-box evidence modes:

- **A**: a no-payment observation of a configured test resource, or local inspection of its returned artifact. This means no funds, not that every HTTP method is free of application side effects. Do not derive a request to execute from an unreviewed Bazaar example.
- **B**: a deliberately selected testnet payment and the associated resource response. On-chain claims require independent transaction/log evidence; a balance difference alone does not identify the operation.
- **C**: RS is configured to use a facilitator provided by the tool; the harness records calls and returns specified outcomes. This tests RS behavior, not the conformance of a real F. A controlled backend witness is additionally needed to prove handler execution/order/non-execution.
- **N**: not assessable through RS alone. Client, facilitator, mechanism-document, authorization-policy, or internal-state tests need their own target/evidence. A/B/C are alternatives only where stated, not proof that every mode completely establishes the requirement.

No funds are needed for C when a local fixture models the protocol. A simulated successful settlement is not a blockchain settlement. Report which evidence was used, the selected offer/ATM/flow, applicable extension, exact source clause, and unresolved prerequisites.

Source abbreviations (line numbers refer to the pinned files):

| Key | File |
| --- | --- |
| C | [Core](../spec/x402-specification-v2.md) |
| H | [HTTP](../spec/transports-v2_http.md) |
| X | [Exact](../spec/schemes_exact_scheme_exact.md) |
| E | [Exact EVM](../spec/schemes_exact_scheme_exact_evm.md) |
| BZ | [Bazaar](../spec/extensions_bazaar.md) |
| PI | [Payment identifier](../spec/extensions_payment_identifier.md) |
| SX | [Sign-in-with-x](../spec/extensions_sign-in-with-x.md) |
| OR | [Offer and receipt](../spec/extensions_extension-offer-and-receipt.md) |

## Core schemas

Optional fields have a conditional type contract when present. Tables below separate their optionality from required fields. The core does not state `additionalProperties: false`, a nonempty `accepts` minimum, an amount regex, a maximum header size, or universal positivity/integer constraints for every numeric field. Do not manufacture those as core MUSTs.

| ID | Role | Level | Source and quoted clause | Requirement and evidence |
| --- | --- | --- | --- | --- |
| CORE-5.1-01 | RS | MUST (schema) | C:114, “must be 2” | `PaymentRequired.x402Version` is the number 2. A. |
| CORE-5.1-02 | RS | MUST (schema) | C:116, “ResourceInfo object” | `PaymentRequired.resource` is a required object. A. |
| CORE-5.1-03 | RS | MUST (schema) | C:117, “Array of payment requirement objects” | `accepts` is a required array of PaymentRequirements. A; see ambiguity A01 for empty arrays. |
| CORE-5.1-04 | RS | MAY | C:115, “Optional” | `error` may be absent; if present its type is string. A. Do not require a particular human message. |
| CORE-5.1-05 | RS | MAY | C:118, “Optional” | `extensions` may be absent; if present its type is object. A. |
| CORE-5.1-06 | RS | MUST (schema) | C:124, “scheme … string … Required” | Every requirement has a string scheme identifier. A. Not every server must offer `exact`. |
| CORE-5.1-07 | RS | MUST (schema) | C:125, “CAIP-2 format” | Every requirement has a string network in CAIP-2 form. A; full CAIP-2 grammar is an external dependency, not defined here. |
| CORE-5.1-08 | RS | MUST (schema) | C:126, “string … atomic token units” | `amount` is a string expressing atomic units. A. No floating-point conversion for value comparisons. |
| CORE-5.1-09 | RS | MUST (schema) | C:127, “Token contract address or ISO 4217 currency code” | `asset` is a required string; interpretation depends on mechanism. A. Do not impose an EVM address on every scheme. |
| CORE-5.1-10 | RS | MUST (schema) | C:128, “Recipient wallet address or role constant” | `payTo` is a required string; interpret by mechanism. A. |
| CORE-5.1-11 | RS | MUST (schema) | C:129, “number … Maximum time allowed for payment completion” | `maxTimeoutSeconds` is a required number. A. Its exact relation to a signature's validity window is mechanism-specific. |
| CORE-5.1-12 | RS | MAY | C:130, “extra … object … Optional” | `extra` is optional, object when present. A. Reserved keys still have defined semantics. |
| CORE-5.1-13 | RS | MUST (schema) | C:136, “URL of the protected resource” | ResourceInfo requires string `url`. A. Exact URL normalization/equality policy is not specified here. |
| CORE-5.1-14 | RS | MAY | C:137, “description … string … Optional” | Optional description is a string. A. |
| CORE-5.1-15 | RS | MAY | C:138, “mimeType … string … Optional” | Optional expected MIME type is a string. A. |
| CORE-5.1-16 | RS | MUST (schema, conditional) | C:139, “Printable ASCII, max 32 characters” | If serviceName is present, enforce string/ASCII/length contract. A; Bazaar has additional extraction rules. |
| CORE-5.1-17 | RS | MUST (schema, conditional) | C:140, “Max 5 entries … max 32 characters” | If tags are present, array of at most five printable-ASCII strings, each at most 32 characters. A. |
| CORE-5.1-18 | RS | MUST (schema, conditional) | C:141, “Absolute `https`/`http` URL … Max 2048 characters” | Optional iconUrl has that type/URL/length contract. A; consumer soft-drop rules are separate. |
| CORE-5.1-19 | RS | MUST (schema, conditional) | C:143-148, “info … Required”; “schema … Required” | Each advertised standard extension has object info and object schema. A; extension-specific shape exceptions/semantics must be resolved explicitly. |
| CORE-5.1-20 | RS/CL | MUST (prose, conditional) | C:150, “Servers advertise … clients echo them” | Extension advertisement/echo is the core pattern. A inspects RS; C can inspect the client's echoed payload; CL obligations are not RS failures. |
| CORE-5.1-21 | CL | MUST (prose) | C:150, “must include at least the info received” | Preserve server-provided extension info; do not delete or overwrite it. N for RS-only; tool self-test or C trace. |
| CORE-5.1-22 | CL | MAY | C:150, “may append additional info” | Client may add extension info. N for RS-only; extension contract controls meaning. |
| CORE-5.2-01 | CL | MUST (schema) | C:199, “x402Version … number … Required” | PaymentPayload includes numeric protocol version; v2 profile uses 2. N as client construction; C observes forwarding. |
| CORE-5.2-02 | CL | MAY | C:200, “resource … Optional” | PaymentPayload.resource is optional. B/C can demonstrate interoperability without it when no selected extension requires it; absence is not intrinsically malformed. |
| CORE-5.2-03 | CL | MUST (schema) | C:201, “accepted … PaymentRequirements object” | Required accepted object identifies the selected payment method, using the requirement schema. N as sender contract; C observes forwarded request. |
| CORE-5.2-04 | CL | MUST (schema) | C:202, “payload … object … Required” | Required object contains mechanism-specific data. N/C. |
| CORE-5.2-05 | CL | MAY | C:203, “extensions … Optional” | Extensions may be absent in core; selected extension requirements can make content necessary. N/C. |
| CORE-5.2-06 | CL | Example | C:207, “For example, with exact EVM scheme” | The signature/authorization table is not a universal shape for Permit2, ERC-7710, or non-EVM payloads. Select the mechanism before validating. A/C local classification. |
| CORE-5.3-01 | F/RS | MUST (schema) | C:246, “success … boolean … Required” | SettlementResponse requires boolean success. B observes RS; C tests its handling; F itself needs direct tests. |
| CORE-5.3-02 | F/RS | MUST (schema) | C:249, “transaction … string … Required” | Required transaction string; empty if no transaction broadcast. B/C, with outcome context. |
| CORE-5.3-03 | F/RS | MUST (schema) | C:250, “network … CAIP-2 format” | Required network string in settlement response. B/C. |
| CORE-5.3-04 | F/RS | MUST (schema, conditional) | C:247, “omitted if successful” | Optional string errorReason describes failed settlement and is absent on successful settlement. B/C. |
| CORE-5.3-05 | F/RS | MAY | C:248, “payer … Optional” | Payer is optional string; omission alone cannot fail core receipt validation. B/C. |
| CORE-5.3-06 | F/RS | MAY | C:251, “actual amount settled … omitted if not applicable” | Optional amount string is settled atomic amount, not necessarily the offered ceiling of another scheme. B/C. |
| CORE-5.3-07 | F/RS | MAY | C:252, “extensions … Optional” | Settlement extensions are optional objects and are distinct from the internal sidechannel. B/C. |
| CORE-5.4-01 | F | MUST (schema) | C:263, “isValid … boolean … Required” | VerifyResponse requires boolean isValid. N for RS-only; C exercises RS consumption, not real F correctness. |
| CORE-5.4-02 | F | MUST (schema, conditional) | C:264, “omitted if valid” | Optional string invalidReason is absent if isValid is true. N/C. |
| CORE-5.4-03 | F | MAY | C:265, “payer … Optional” | Verify payer is optional string. N/C. |
| CORE-5.4-04 | F | MAY | C:266, “extensions … Optional” | Verify extensions are optional object. N/C. |
| CORE-5.4-05 | F | MAY | C:267, “extra … Optional” | Verify scheme-specific extra is optional object. N/C. |

## Payment flow and facilitator boundary

| ID | Role | Level | Source and quoted clause | Requirement and evidence |
| --- | --- | --- | --- | --- |
| CORE-2-01 | RS | MUST (prose) | C:41, “If no valid payment is attached” | A configured paid resource signals payment required and provides requirements. A. Existing authorized access/free routes need explicit scenario preconditions. |
| CORE-6.1-01 | RS/CL | MUST | C:285, “MUST interpret them as defined here” | Treat extra.assetTransferMethod and extra.paymentFlow as reserved protocol keys. A observes offers; C/local profile tests behavior. |
| CORE-6.1-02 | RS/CL | MUST (prose) | C:289, “means the mechanism default” | Resolve omitted ATM/flow through mechanism defaults, not a global arbitrary default. A/C; absent binding information is cannot-assess. |
| CORE-6.1-03 | RS | MUST | C:289, “When … not `authorization` … MUST be present” | Explicitly advertise non-authorization resolved flows in accepts[].extra.paymentFlow. A plus declared mechanism/profile; cannot infer hidden actual flow from one challenge. |
| CORE-6.1-04 | RS | MAY | C:289, “authorization MAY be omitted or explicit” | Both omitted default authorization and explicit authorization are allowed. A. |
| CORE-6.1-05 | RS | MUST | C:289, “MUST reject unsupported … combinations” | Accept only supported ATM/flow combinations. C in a configured fixture; support set must be known. A cannot establish all rejection behavior. |
| CORE-6.1-06 | CL | MUST NOT | C:289, “MUST NOT construct a payment … do not recognize” | Client must understand selected flow before construction. N for RS; tool selection/self-tests. |
| CORE-6.1-07 | CL | SHOULD | C:289, “SHOULD skip such … entries” | Skip unrecognized flows during selection. N for RS; tool self-tests. |
| CORE-6.1-08 | CL | SHOULD | C:289, “SHOULD prefer `authorization`” | Prefer authorization over pre-handler commitment when both are offered for the request. N for RS; tool selection report. |
| CORE-6.1-09 | RS | MUST (prose) | C:295, “verify → resource → settle → respond” | Authorization ordering; funds move only after successful resource completion. C plus backend witness; B only observes an instance, not complete ordering. |
| CORE-6.1-10 | RS | MUST (prose, conditional) | C:296, “settle → resource → respond” | Upfront settles before resource; verify is not part of this ordering. C plus backend witness. |
| CORE-6.1-11 | RS | MUST (prose, conditional) | C:297, “settle → resource → settle → respond” | Escrow's two distinct settlement stages surround resource execution. C plus mechanism fixture/backend witness; not an exact EVM default. |
| CORE-6.1-12 | RS | MUST | C:299, “at least one check … MUST run before the resource executes” | Observe a pre-handler verify or settle. C plus backend witness. A 402 by itself does not prove no handler ran. |
| CORE-7.1-01 | F | MUST NOT | C:307, “MUST NOT commit payment state or write onchain state” | Verify is read-only. N for RS-only; controlling a fake F cannot certify a real F. |
| CORE-7.1-02 | RS/F | MUST (prose) | C:305-320, “POST /verify”; request envelope | In flows using verify, facilitator HTTP request carries x402Version, paymentPayload, paymentRequirements. C records request. Field-level requiredness is prose/example-derived, not a separate table. |
| CORE-7.2-01 | F | MUST (prose) | C:395, “Durably commits payment state for the request” | Settle commits according to the mechanism; not necessarily a final charge or on-chain write in every scheme. N for real F; B ledger evidence for selected EVM mechanism. |
| CORE-7.2-02 | RS/F | MUST (prose) | C:397, “Same structure as `/verify`” | Settle uses corresponding envelope on POST /settle. C. Requirements may have scheme-defined stage semantics. |
| CORE-7.2-03 | RS/F | MAY | C:401, “MAY be invoked more than once” | Multiple settles are not universally forbidden. C only with a mechanism defining the stages. |
| CORE-7.2-04 | M | MUST | C:401, “MUST specify how … distinguishes them” | Multi-settle schemes must define stage discrimination. N; inspect the mechanism document. |
| CORE-7.2.1-01 | F | MAY | C:428, “MAY communicate extension-specific … outcomes” | Sidechannel support is optional. N/C. |
| CORE-7.2.1-02 | F | MUST (prose, conditional) | C:430-437, “EXTENSION-RESPONSES”; “Base64-encoded JSON object” | HTTP sidechannel is that header, with a JSON object keyed by extension. N/C. |
| CORE-7.2.1-03 | F/RS | MUST NOT (prose) | C:428, “not part of the JSON response body … not forwarded to buyers” | Internal extension outcomes stay out of buyer responses. C can provide a benign marker and inspect buyer headers/body/decoded protocol objects. Absence in one ordinary response is not full evidence. |
| CORE-7.3-01 | F | MUST (schema) | C:481, “kinds … array … Required” | SupportedResponse requires kinds array. N for RS-only; direct configured F endpoint. |
| CORE-7.3-02 | F | MUST (schema) | C:482, “extensions … array … Required” | SupportedResponse requires extension identifier array. N. |
| CORE-7.3-03 | F | MUST (schema) | C:483, “signers … object … Required” | SupportedResponse requires CAIP-2-pattern-to-signer map. N. |
| CORE-7.3-04 | F | MUST (schema) | C:489, “2 for v2” | Each supported kind includes numeric x402Version. N. |
| CORE-7.3-05 | F | MUST (schema) | C:490, “scheme … string … Required” | Supported kind requires scheme string. N. |
| CORE-7.3-06 | F | MUST (schema) | C:491, “network … CAIP-2 format” | Supported kind requires network string; optional extra is object. N. |
| CORE-9-01 | F/RS | MAY | C:591, “error codes that may be returned” | Listed general error strings are not a universal exact-message mandate. A/B/C report semantic category plus observed code. |
| CORE-9-02 | F | MAY | C:608, “MAY return this non-terminal code” | settlement_pending is allowed for broadcast with unestablished confirmation. N for real F; C exercises RS. |
| CORE-9-03 | F/RS | MUST | C:608, “MUST carry a non-empty `transaction` … and `network`” | A receipt with errorReason settlement_pending identifies the broadcast and network. B if observed, C fixture; the code does not mean terminal failure. |
| CORE-10-01 | CL/F | MUST (prose, EIP-3009) | C:616-619, “unique 32-byte nonce”; “explicit valid time windows” | EIP-3009 authorizations use nonce/time/signature protections. N for internal validation; B supports one observed transfer outcome. Do not generalize this mechanism's nonce to all x402. |
| CORE-12-01 | RS | Example | C:14-20,719, “Session handling mechanisms”; “implementation guides” | A one-hour pass, token name, purchase endpoint, reconciliation API, retention duration, and custom settlement header are not core x402 requirements. Absence is not a failure. |

## HTTP transport

| ID | Role | Level | Source and quoted clause | Requirement and evidence |
| --- | --- | --- | --- | --- |
| HTTP-REQUIRED-01 | RS | MUST (prose) | H:7-15, “HTTP 402 … with `PAYMENT-REQUIRED` header” | Initial payment-required signaling uses 402 plus base64-encoded PaymentRequired JSON in the response header. A. Settlement failure is a separate scenario. |
| HTTP-PAYLOAD-01 | CL/RS | MUST (prose) | H:55-60, “`PAYMENT-SIGNATURE` HTTP header” | Payment payload transmission uses base64 JSON PaymentPayload in that header. B/C exercises the transport. Header casing is not a payment protocol discriminator. |
| HTTP-RESPONSE-01 | RS | MUST (prose) | H:111-116, “`PAYMENT-RESPONSE` header” | Settlement results use base64 JSON SettlementResponse in the response header. B/C. Receipt success/fields must be checked independently of status. |
| HTTP-BODY-01 | RS | MAY | H:172-174, “Response bodies are a server implementation concern” | HTML, JSON, text, empty challenge bodies, and ordinary backend content are allowed. No requirement that response body mirror a header. A/B/C. |
| HTTP-ERROR-01 | RS | MUST (prose) | H:182, “Payment Required … 402” | Payment-needed category maps to 402. A. |
| HTTP-ERROR-02 | RS | MUST (prose) | H:183, “Invalid Payment … 400” | Malformed payload/requirements category maps to 400. C/local malformed-message fixture; distinguish failed verification from malformed syntax. |
| HTTP-ERROR-03 | RS | MUST (prose) | H:184, “Payment Failed … 402” | Verification or settlement failure category maps to 402. C; pending is non-terminal and not automatically this category. |
| HTTP-ERROR-04 | RS | MUST (prose) | H:185, “Server Error … 500” | Payment-processing internal server-error category maps to 500. C with a classified scenario; an arbitrary backend 5xx is not automatically this category. |
| HTTP-ERROR-05 | RS | MUST (prose) | H:186, “Success … 200” | Successful verified-and-settled category maps to200 in this table. B/C; other application-success codes are a documented interpretation issue, not silently accepted or globally rejected. |
| HTTP-EXAMPLE-01 | RS | Example | H:144-162, “Example (Failure)” | The failure example has PAYMENT-RESPONSE and no PAYMENT-REQUIRED. Do not require fresh payment terms on every 402. A decoded receipt of failure is not an initial challenge. |

## Exact scheme and EVM binding

Supporting one exact mechanism does not imply support for all exact networks or all three EVM ATMs. Attribute insufficient coverage of an advertised ATM to the tool, not to the target. Other-network validation paragraphs in X:62-90 remain conditional on those networks; their complete mechanism documents are outside this snapshot.

| ID | Role | Level | Source and quoted clause | Requirement and evidence |
| --- | --- | --- | --- | --- |
| EXACT-SUMMARY-01 | RS/F | MUST (prose) | X:5-6, “must know in advance the exact amount” | Exact transfers a specified, known amount. A inspects quote; B checks identifiable transfer; C verifies amount passed to F. |
| EXACT-FLOW-01 | RS/CL | MUST (prose) | X:16, “By default … authorization” | Exact defaults to authorization unless the mechanism/offer resolves otherwise. A/C. |
| EXACT-FLOW-02 | RS | MAY | X:18, “MAY also use … upfront” | Exact upfront is allowed. A/C; explicit flow advertisement still applies. |
| EXACT-FLOW-03 | RS/CL | SHOULD | X:20, “authorization SHOULD be preferred” | Prefer post-handler commitment where possible. A shows the offered alternatives; motivation for server choice is N. |
| EXACT-FLOW-04 | RS/M | SHOULD | X:20, “SHOULD offer upfront” | Bounded method/long handler may warrant upfront. N without declared handler bounds. |
| EXACT-FLOW-05 | RS/CL | Example | X:20, “this specification defines no refund” | Upfront handler failure does not imply automatic refund nonconformance; record settlement and resource outcome separately. B/C. |
| EXACT-METHOD-01 | M | MUST | X:24, “MUST state which family” | A method declares facilitator-submitted or client-submitted family. N: mechanism-document review. |
| EXACT-FS-01 | M | MUST | X:30-32, “Each method MUST declare … Fee payer” | Declare who pays the network fee. N. |
| EXACT-FS-02 | M | MUST | X:30,33, “Replay primitive” | Declare exclusive/shared primitive and shared-state concurrency/invalidation limitations. N. |
| EXACT-FS-03 | M | MUST | X:30,34, “Validity window” | Declare bounds, or invalidation/retention for unbounded signed payments. N. |
| EXACT-FS-04 | M | MUST | X:30,35, “Duplicate submission” | Declare whether a network distinguishes duplicate submission. N. |
| EXACT-FS-05 | F | MUST | X:39, “exactly one identifiable transfer” | Settlement transfers exactly amount of asset to payTo. B requires transaction/log attribution, not just receipt flag or wallet balance delta. |
| EXACT-FS-06 | F | MUST (prose) | X:40, “no operation … may debit the facilitator beyond that fee” | Sponsored settlement does not debit sponsor principal. N for RS-only; direct controlled F/ledger fixture needed. |
| EXACT-FS-07 | F | MUST | X:41, “consumed primitive MUST produce a settlement failure” | Network-consumed primitive cannot be reported as fresh settlement success. N for RS-only; cached RS response is not a new facilitator settlement. |
| EXACT-FS-08 | F | MUST (conditional) | X:42, “MUST deduplicate settlements atomically across every process” | Indistinguishable-submission methods require shared atomic deduplication until payment cannot land. N for RS-only; a single sequential retry cannot prove it. |
| EXACT-CS-01 | M/RS/CL | MUST | X:46, “MUST use upfront” | Client-submitted proof mechanisms use upfront flow. A if advertised; C with binding fixture. |
| EXACT-CS-02 | M/RS | MUST | X:50, “instrument … MUST be advertised … together with its validity window” | Advertise payment instrument and validity. A with mechanism schema. |
| EXACT-CS-03 | CL | MUST | X:50, “proof artifact MUST be carried in PaymentPayload.payload” | Proof belongs in payload. N/C. |
| EXACT-CS-04 | M | SHOULD | X:50, “Self-verifying proofs … SHOULD be preferred” | Preference applies to method design; no mandate to implement every proof family. N. |
| EXACT-CS-05 | M/F | MUST | X:51, “MUST bind the payment to the requirements” | Method specifies request binding by one of the listed approaches. N for RS-only; controlled mechanism tests. |
| EXACT-CS-06 | F | MUST | X:52, “claimed atomically before the resource executes” | Proof consumption precedes resource execution with a single successful claim. N/C plus backend witness for RS boundary; not a general-purpose remote concurrency test. |
| EXACT-CS-07 | M/F | MUST | X:52, “MUST define a canonical consumption key” | Consumption key combines CAIP-2 network and canonical network payment ID. N. |
| EXACT-CS-08 | M/F | MUST | X:53, “for as long as it stays presentable” | Consumption retention covers proof presentation lifetime; otherwise declare max age or unbounded retention. N; finite runs cannot establish lifetime guarantees. |
| EXACT-CS-09 | M | MUST | X:54, “MUST state how a non-conforming payment … is handled” | Define under/overpayment handling and any return path. N. |
| EXACT-CS-10 | M | MUST (prose) | X:55, “declare the observable event … final” | Define finality event, confirmation policy owner, stage boundary. N. |
| EXACT-CS-11 | F/RS | MUST NOT | X:55, “MUST NOT consume the proof or deliver the resource” | Before reachable finality, neither final consumption nor resource delivery occurs. N for real F; C plus witness for RS behavior. |
| EXACT-CS-12 | F | MUST | X:55, “MUST return an error naming the unmet condition” | Unmet finality is named; in-flight claim is released, abnormal termination cannot claim forever. N for RS-only; controlled F state fixture. |
| EXACT-CS-13 | M | MUST | X:56, “MUST state whether the payment is returned” | Define disposition after irreversible finality failure. N. |
| EXACT-CS-14 | CL | MUST NOT | X:56, “MUST NOT assume a return path exists” | Client cannot assume refund. N; tool payment UX must reflect declared behavior. |
| EVM-SUMMARY-01 | F | MUST (prose) | E:5, “Facilitator … pays the gas” | EVM exact profile sponsors transaction gas. B ledger evidence; a fake F does not prove it. |
| EVM-ATM-01 | CL | SHOULD (prose/default) | E:15, “default to eip3009” | Omitted EVM ATM resolves to eip3009. A/local selection; not permit2 inferred from token metadata. |
| EVM-ATM-02 | CL | SHOULD (prose) | E:15, “should echo the selected assetTransferMethod” | Echo nondefault ATM in accepted.extra. N/C. |
| EVM-3009-01 | CL | MUST (prose) | E:27-29, “must contain … 65-byte signature” | EIP-3009 payload has transferWithAuthorization signature. N as client construction; C observes shape. Smart-wallet interpretation requires clarification, not a guessed exception. |
| EVM-3009-02 | CL | MUST (prose) | E:27,30; C:214-223, “authorization … parameters” | Authorization has string from, to, value, validAfter, validBefore and 32-byte nonce. N/C; inspect each field/type separately in tests. |
| EVM-3009-03 | RS | MUST (conditional) | E:71, “if present, MUST be eip3009” | Explicit ATM for this method is eip3009; absence is allowed. A. |
| EVM-3009-04 | RS | MUST (schema) | E:72, “extra.name (required)” | Provide token EIP-712 domain name. A; actual correctness requires token evidence beyond string presence. |
| EVM-3009-05 | RS | MUST (schema) | E:73, “extra.version (required)” | Provide token EIP-712 domain version. A/B with token evidence. |
| EVM-3009-06 | F | MUST (prose) | E:77, “Verify … recovers to authorization.from” | Verify signature and payer identity. N for RS-only; C tests RS reaction to a verifier result, not cryptographic implementation. |
| EVM-3009-07 | F | MUST (prose) | E:78, “sufficient balance” | Check payer asset balance. N/B observes particular outcome. |
| EVM-3009-08 | F | MUST (prose) | E:79, “Amount, Validity Window … meet … Requirements” | Validate exact amount and authorization window. N for implementation; mechanism fixtures needed for comprehensive checks. |
| EVM-3009-09 | F | MUST (prose) | E:80, “Token and Network match” | Verify token/network match requirements. N/C boundary only. |
| EVM-3009-10 | F | MUST (prose) | E:81, “Simulate … to ensure success” | EIP-3009 verification calls for simulation. N; public success does not reveal whether simulation ran. |
| EVM-3009-11 | F | MUST (prose) | E:85, “calling … transferWithAuthorization” | Settle using supplied signature/authorization on compliant token. B transaction evidence. |
| EVM-3009-12 | F | MAY | E:87, “MAY return settlement_pending” | Broadcast with unknown confirmation may return pending with transaction hash. N/C; no mandatory terminal error on timeout. |
| EVM-PERMIT2-01 | CL/F | MAY | E:97-117, “supports three ways” | Direct approval or separately supported sponsored approval/EIP-2612 are alternatives; no universal sponsorship requirement. A declared capability, B setup-dependent, N for unavailable extension specs. |
| EVM-PERMIT2-02 | CL | MUST (prose) | E:121-124, “must contain … signature … permit2Authorization” | Permit2 payload has those fields. N/C. |
| EVM-PERMIT2-03 | CL/F | MUST (prose) | E:126, “spender … x402ExactPermit2Proxy, not the Facilitator” | Spender is designated proxy. N/B cryptographic/transaction evidence. |
| EVM-PERMIT2-04 | RS | MUST | E:170, “MUST be permit2” | Requirements explicitly identify Permit2. A. |
| EVM-PERMIT2-05 | RS | MUST (schema, conditional) | E:171, “Required when … EIP-2612” | Token domain name required under the stated EIP-2612 condition. A plus token capability. |
| EVM-PERMIT2-06 | RS | MUST (schema, conditional) | E:172, “Required when … EIP-2612” | Token domain version required under that condition. A plus token capability. |
| EVM-PERMIT2-07 | F | MUST (prose) | E:176-178, “must execute these checks in order” | Start with signature recovery to permit2Authorization.from. N for internal ordering. |
| EVM-PERMIT2-08 | F | MUST (prose) | E:180-185, “412 Precondition Failed … PERMIT2_ALLOWANCE_REQUIRED” | Insufficient allowance without either supported alternative triggers stated precondition response. N/direct F; C can test RS propagation where specified. |
| EVM-PERMIT2-09 | F | MUST (prose) | E:187, “sufficient balance” | Verify payer asset balance. N. |
| EVM-PERMIT2-10 | F | MUST (prose) | E:189, “amount covers the payment” | Check amount, subject to exact transfer semantics and the field-path inconsistency A07. N/B. |
| EVM-PERMIT2-11 | F | MUST (prose) | E:191, “deadline (not expired) … validAfter (active)” | Verify validity window. N. |
| EVM-PERMIT2-12 | F | MUST (prose) | E:193, “Token and Network match” | Check token/network. N. |
| EVM-PERMIT2-13 | F | SHOULD | E:195-201, “Simulation (Recommended)” | Simulation is recommended; re-verify-before-settle is an allowed alternative. N; do not copy EIP-3009's imperative strength here. |
| EVM-PERMIT2-14 | F | MUST (prose) | E:205-208, “call … settle” | Standard allowance settles through proxy. B transaction evidence. |
| EVM-PERMIT2-15 | F | MUST (prose, conditional) | E:211, “strictly before … settle” | Sponsored approval precedes settle in its batch. N/B with extension and transaction evidence. |
| EVM-PERMIT2-16 | F | MUST (prose, conditional) | E:214, “call … settleWithPermit” | EIP-2612 path uses designated proxy entry point. N/B. |
| EVM-PERMIT2-17 | F | MAY | E:216, “MAY return settlement_pending” | Pending has the same core transaction/network requirements. N/C. |
| EVM-7710-01 | CL/F | MUST (prose, conditional) | E:226-230, “following must be true” | ERC-7710 needs a compatible delegator, deployed manager and active delegation; these are profile prerequisites. N/B configured setup. |
| EVM-7710-02 | CL | MUST (prose) | E:245-249, “must contain” | Payload requires delegationManager, permissionContext, delegator. N/C. |
| EVM-7710-03 | RS | MUST | E:284, “MUST be erc7710” | Requirements explicitly identify erc7710. A. |
| EVM-7710-04 | RS | MAY | E:285-286, “Not required” | Domain name/version are optional here. A. |
| EVM-7710-05 | F | MUST (prose) | E:292-305, “entirely through simulation” | Construct intended transfer/mode and simulate redeemDelegations to establish delegation validity, balance and success. N; external success cannot reveal validation algorithm. |
| EVM-7710-06 | F | MUST (prose) | E:320-330, “calling redeemDelegations” | Settlement executes delegated token.transfer(payTo, amount). B transaction evidence. |
| EVM-7710-07 | F | SHOULD (prose) | E:314-316, “should always set an explicit gas limit” | Apply gas-limit/simulation guidance in direct F implementation. N; no resource-server oracle. |
| EVM-ANNEX-01 | CL/F | MUST (prose/profile) | E:358-360, “Canonical Address” | Pinned proxy address is part of this snapshot's Permit2 profile; do not discover a replacement from examples or silently track latest. N/B. Canonical Permit2 address itself is only externally linked. |

The non-EVM paragraphs X:64-90 specify additional requirements for SVM, Stellar, TON and Starknet. They are not an EVM resource-server acceptance criterion. A future profile must import the referenced binding and extract its field, signature, simulation and ledger rules; until then report those mechanisms as `cannot-assess` when advertised, not globally conformant because their core JSON passed.

## Bazaar and discovery

Advertising Bazaar, cataloging at a facilitator, and exposing a discovery API are separate capabilities. A valid declaration alone does not prove publication, searchability, payment validity or successful service delivery. Schema tests inspect the declared contract and its info independently; merely accepting an empty schema does not establish the required discriminator constraints.

| ID | Role | Level | Source and quoted clause | Requirement and evidence |
| --- | --- | --- | --- | --- |
| BAZAAR-DECL-01 | RS | MAY | BZ:5-15, “advertises … including the bazaar extension” | Optional declaration belongs in PaymentRequired.extensions.bazaar with info/schema. A. Missing Bazaar is not a core failure. |
| BAZAAR-INPUT-01 | RS | MUST (prose, conditional) | BZ:17-19, “discriminated union … type” | info.input discriminates HTTP versus MCP. A. |
| BAZAAR-HTTP-01 | RS | MUST (schema) | BZ:255-256, “Always http”; “GET, HEAD, DELETE” | Query-method input requires type=http and a listed method. A. |
| BAZAAR-HTTP-02 | RS | MAY | BZ:257, “queryParams … No” | Query parameter examples are optional objects. A. |
| BAZAAR-HTTP-03 | RS | MAY | BZ:258, “headers … No” | Header examples are optional objects. A. |
| BAZAAR-HTTP-04 | RS | MUST (schema) | BZ:264-265, “Always http”; “POST, PUT, PATCH” | Body-method input requires type=http and a listed method. A. |
| BAZAAR-HTTP-05 | RS | MUST (schema) | BZ:266, “json, form-data, text” | Body methods require one listed bodyType. A. |
| BAZAAR-HTTP-06 | RS | MUST (schema) | BZ:267, “body … object/string … Yes” | Required body example can be object or string, despite the narrower POST example. A. |
| BAZAAR-HTTP-07 | RS | MAY | BZ:268-269, “No” | Body methods may also provide queryParams and headers objects. A. |
| BAZAAR-MCP-01 | RS | MUST (schema) | BZ:275, “Always mcp” | MCP input requires type=mcp. A declaration only; HTTP-only tool cannot certify MCP invocation. |
| BAZAAR-MCP-02 | RS | MUST (schema) | BZ:276, “toolName … Yes” | MCP toolName is required string matching the tool call name. A structural; actual tool match needs MCP evidence. |
| BAZAAR-MCP-03 | RS | MUST (schema) | BZ:278, “inputSchema … Yes” | Required MCP argument schema is object with referenced MCP semantics. A partially; full external MCP schema is not supplied. |
| BAZAAR-MCP-04 | RS | MAY | BZ:277,279-280, “No”; “Defaults to streamable-http” | Optional description string, transport streamable-http/sse, example object; omitted transport defaults to streamable-http. A. |
| BAZAAR-MCP-05 | F | MUST (prose) | BZ:282, “must use both fields” | Catalog MCP identity by resource URL and toolName. N for RS-only; direct configured catalog can expose outcome. |
| BAZAAR-OUTPUT-01 | RS | MAY | BZ:286, “output object (optional)” | Output is optional. A. |
| BAZAAR-OUTPUT-02 | RS | MUST (schema, conditional) | BZ:290, “type … Yes” | Present output requires string type. A. |
| BAZAAR-OUTPUT-03 | RS | MAY | BZ:291-292, “format … No”; “example … any” | Optional format string; output example may be any JSON value, not object-only. A. |
| BAZAAR-OUTPUT-04 | F | SHOULD (prose) | BZ:294, “should assume arbitrary text” | Missing MCP output defaults to arbitrary text for facilitator interpretation. N. |
| BAZAAR-SCHEMA-01 | RS/F | MUST (prose) | BZ:315, “Must use JSON Schema Draft 2020-12” | Bazaar schema uses that dialect. A schema inspection; a generic core extension is not thereby forced to that dialect. |
| BAZAAR-SCHEMA-02 | RS | MUST (prose) | BZ:316, “Must define an input property (required)” | Schema defines and requires input. A. |
| BAZAAR-SCHEMA-03 | RS | MUST (prose) | BZ:318, “Must validate that input.type equals” | Schema constrains the expected discriminator. A offline schema assessment. |
| BAZAAR-SCHEMA-04 | RS | MUST (prose) | BZ:319, “appropriate method enum” | HTTP schema constrains applicable method set. A offline schema assessment. |
| BAZAAR-SCHEMA-05 | RS | MUST (prose) | BZ:320, “Must require toolName and inputSchema” | MCP schema requires both fields. A. |
| BAZAAR-SCHEMA-06 | RS/F | MUST (prose) | BZ:321, “same-document JSON Pointer fragments” | `$ref` and `$id` values cannot designate external resources; allowed form is same-document fragment per text. A offline inspection. `$schema` is a distinct keyword, not banned by this clause. |
| BAZAAR-SCHEMA-07 | F | MUST (prose) | BZ:323, “must validate info against schema before cataloging” | Catalog only after schema validation. N for RS-only; catalog implementation fixture. |
| BAZAAR-SCHEMA-08 | F | MUST NOT (prose) | BZ:323, “must not resolve external … values” | Validator does not resolve external schema references. N; local validator configuration/source tests, no external retrieval probe needed. |
| BAZAAR-META-01 | RS | MAY | BZ:362-377, “MAY publish … top-level resource object” | Service metadata belongs on resource, not inside Bazaar info. A. |
| BAZAAR-META-02 | CL/F | MUST | BZ:383-389, “MUST apply … soft-drop rules” | Drop invalid/nonempty-printable-ASCII serviceName >32 chars; retain surrounding metadata. N for RS-only; offline extractor tests. |
| BAZAAR-META-03 | CL/F | MUST | BZ:383-390, “first 5 valid entries”; “first occurrence wins” | Tags: discard invalid entries, ASCII/nonempty/≤32, case-insensitive deduplication, first five valid. N/local extractor; server declaration limits remain CORE-5.1-17. |
| BAZAAR-META-04 | CL/F | MUST | BZ:383-391, “Drop the field” | iconUrl obeys the complete URL/host/length/control-character rule from the pinned table; invalid field is dropped, not whole metadata. N/local extractor. |
| BAZAAR-META-05 | CL/F | MUST | BZ:393-395, “MUST percent-decode … host” | Apply specified host normalization before host checks. N/local extractor. |
| BAZAAR-CATALOG-01 | F | SHOULD (prose) | BZ:424-427, “should … Extract” | Extract discovery data after validation. N for RS-only. Storage/indexing strategy is implementation-specific. |
| BAZAAR-DISCOVERY-01 | F/D | MAY | BZ:429-433, “may expose discovery APIs” | List/search endpoint exposure is optional, including on a Bazaar-capable facilitator. A on explicitly configured discovery service; never require on resource-server origin. |
| BAZAAR-DISCOVERY-02 | D | MAY | C:506-514; BZ:439-447, “Optional” | List supports optional type/payTo/scheme/network/extensions/limit/offset parameters per advertised API; core states limit 1–100 default20, offset0. A configured D. |
| BAZAAR-DISCOVERY-03 | D | MUST (schema, conditional) | C:560, “resource … string … Required” | A discovered item requires resource identifier string. A configured D. |
| BAZAAR-DISCOVERY-04 | D | MUST (schema, conditional) | C:561, “type … string … Required” | Item requires resource type string. A. HTTP-only wording in core does not erase Bazaar MCP support. |
| BAZAAR-DISCOVERY-05 | D | MUST (schema, conditional) | C:562, “x402Version … number … Required” | Item requires numeric version. A. |
| BAZAAR-DISCOVERY-06 | D | MUST (schema, conditional) | C:563, “accepts … array … Required” | Item requires PaymentRequirements array. A. |
| BAZAAR-DISCOVERY-07 | D | MUST (schema, conditional) | C:564, “ISO 8601 timestamp” | Item requires lastUpdated string timestamp. A. |
| BAZAAR-DISCOVERY-08 | D | MAY | C:565, “extensions … Optional” | Item extensions optional object. A. |
| BAZAAR-SEARCH-01 | CL/D | MUST (schema, conditional) | BZ:455, “query … Yes” | Search request requires a query string. A configured D; not a paid resource operation. |
| BAZAAR-SEARCH-02 | D | MAY | BZ:461-462, “Advisory … may … ignore” | Search limit/cursor advisory; exact page size or continuation support is not mandatory. A. |
| BAZAAR-SEARCH-03 | D | MAY | BZ:468-469, “No” | partialResults optional boolean; pagination optional object or null. A. |
| BAZAAR-SEARCH-04 | D | MUST (schema, conditional) | BZ:470, “Yes (when pagination is an object)” | Present pagination object requires numeric limit. A. |
| BAZAAR-SEARCH-05 | D | MUST (schema, conditional) | BZ:471, “string or null … Yes” | Present pagination object requires cursor string or null. A. |
| BAZAAR-SIDECHANNEL-01 | F | MAY | BZ:485, “MAY append extension outcomes” | Bazaar outcome sidechannel optional on verify/settle. N/C. |
| BAZAAR-SIDECHANNEL-02 | F | MUST (schema, conditional) | BZ:493, “success, processing, or rejected” | Present bazaar sidechannel status uses listed values. N/C. |
| BAZAAR-SIDECHANNEL-03 | F | MUST (schema, conditional) | BZ:494, “Only present when … rejected” | Optional string rejectedReason only belongs to rejected outcome. N/C. |
| BAZAAR-SIDECHANNEL-04 | RS | MUST NOT (prose) | BZ:481, “never forwarded to the buyer” | Internal Bazaar processing outcome is not buyer settlement metadata. C, under CORE-7.2.1-03. |
| BAZAAR-ECHO-01 | CL | SHOULD (prose) | BZ:523, “expected to echo”; “cataloging will not occur” | Echo Bazaar for discovery; absence does not imply base payment must fail. N/C; reconcile with stronger generic core echo prose. |
| BAZAAR-ROUTE-01 | RS | MUST (prose, conditional) | BZ:529-537, “two additional fields” | Dynamic route declaration uses concrete info.input.pathParams and extension-level routeTemplate. A with known dynamic-route configuration. |
| BAZAAR-ROUTE-02 | RS | MUST (prose, conditional) | BZ:541-543, “externally using :paramName”; “absent for static routes” | External template uses colon syntax; static routes omit it. A with declared route kind. Internal framework syntax is not a universal server requirement. |
| BAZAAR-ROUTE-03 | F | MUST | BZ:543, “MUST treat an absent … concrete URL path” | Missing template falls back to concrete path. N for RS-only. |
| BAZAAR-ROUTE-04 | F | MUST | BZ:563, “MUST validate … before using it” | Apply pinned nonempty/leading-slash/character/path rules and percent decoding before relevant checks. N/local catalog fixture. |
| BAZAAR-ROUTE-05 | F | MUST (prose) | BZ:577-579, “discarded … falls back” | Invalid template is discarded with concrete-path fallback. N/local catalog fixture. |
| BAZAAR-V1-01 | F | MAY | BZ:590, “not expected to support v1” | V1 support is optional. A v2 conformance profile does not require v1 outputSchema. |

## Payment identifier

The extension can be consumed at RS, F, or both. Discovery of its key alone does not establish which component caches application responses. Select an explicit consumer profile before claiming RS-level cache semantics; see ambiguity A06.

| ID | Role | Level | Source and quoted clause | Requirement and evidence |
| --- | --- | --- | --- | --- |
| PID-DECL-01 | RS | MAY | PI:5,11,119-120, “either or both points” | Optional payment-identifier advertisement; consumer location is configurable. A declaration; C forwarding. |
| PID-INFO-01 | RS | MUST (prose, conditional) | PI:64-68, “Type: boolean”; “Default: false” | info.required is boolean when provided; false is default. A. Example schema requires it explicitly; flag that distinction. |
| PID-CLIENT-01 | CL | MUST (prose, conditional) | PI:121, “must provide id if … required: true” | Client must supply ID when required. N/tool self-test; C request observation. |
| PID-FORMAT-01 | CL | MUST (prose) | PI:74, “16-128 characters” | Identifier length lies in stated range. N/local payload validator. |
| PID-FORMAT-02 | CL | MUST (prose) | PI:75, “alphanumeric, hyphens, underscores” | Identifier uses listed character family. N; ASCII interpretation should be recorded because PI does not itself define the Unicode range. |
| PID-FORMAT-03 | CL | SHOULD | PI:76, “Recommendation: UUID v4 with prefix” | UUID format/prefix recommended, not mandatory. N/tool self-test. |
| PID-CLIENT-02 | CL | MUST (prose) | PI:38,121, “echoes … appends”; “reuses same id on retries” | Preserve echoed info; generate unique IDs per operation and reuse for retry. N/C. |
| PID-IDEMPOTENCY-01 | RS/F consumer | MUST (prose, profile) | PI:84, “New id … Process request normally” | New ID follows ordinary payment/resource behavior. B or C, explicit consumer profile. |
| PID-IDEMPOTENCY-02 | RS/F consumer | MUST (prose, profile) | PI:85, “Same id, same payload … Return cached response” | Repeat yields cached consumer response. B/C only within fixture-defined retry lifetime. Spec gives no cache retention duration. |
| PID-IDEMPOTENCY-03 | RS/F consumer | MUST (prose, profile) | PI:86, “Same id, different payload … 409 Conflict” | Different operation under same ID conflicts. C/local fixture with well-defined fingerprint; see same-payload ambiguity A06. |
| PID-IDEMPOTENCY-04 | RS/F consumer | MUST (prose, conditional) | PI:87, “required: true, no id … 400 Bad Request” | Required missing ID maps to400. C controlled fixture; RS/F consumer attribution matters. |
| PID-BINDING-01 | RS/F | SHOULD (prose) | PI:91-101, “should bind … normalized request fingerprint” | Bind ID to operation-defining fields, including resource/method as applicable. N for complete internal policy; C observes declared cases. Listed fields are examples, not a canonical hash algorithm. |
| PID-BINDING-02 | RS/F | SHOULD (prose) | PI:103-107, “store the first observed fingerprint” | Preserve first binding; changed binding should conflict instead of reuse/second operation. N/C local fixture. |
| PID-BINDING-03 | RS/F | SHOULD (prose) | PI:109-111, “Scope the key by … boundaries” | Respect relevant tenant/merchant/route/account scopes. N without declared application boundaries. No universal tenant field mandated. |

## Sign-in-with-x

This is RS↔CL authentication, not facilitator payment verification. A prior payment does not imply a universal pass duration, token, or permanent resource entitlement. Black-box functional scenarios need a configured entitlement policy and fresh challenge. Origin/temporal/signature validation should be exercised in a local controlled fixture; this inventory is not an authorization-bypass testing workflow for arbitrary services.

| ID | Role | Level | Source and quoted clause | Requirement and evidence |
| --- | --- | --- | --- | --- |
| SIWX-DECL-01 | RS | MAY | SX:7,11, “Facilitator is not involved”; “advertises … sign-in-with-x” | Optional extension advertised in PaymentRequired.extensions. A. Do not require F to advertise or implement SIWx. |
| SIWX-INFO-01 | RS | MUST (schema) | SX:164, “domain … Required” | Challenge has string public domain. A with configured expected origin. |
| SIWX-INFO-02 | RS | MUST (schema) | SX:165, “Full resource URI” | Challenge has string uri. A. Origin binding and full-resource entitlement are distinct concerns. |
| SIWX-INFO-03 | RS | MUST (schema) | SX:166, “Always 1” | Challenge version is string "1", not x402 numeric2. A. |
| SIWX-INFO-04 | RS | MUST | SX:167, “Server MUST generate this” | Server generates nonce; field describes 32 hex characters. A observes shape/change only, not entropy quality or global uniqueness. |
| SIWX-INFO-05 | RS | MUST (schema) | SX:168, “ISO 8601 timestamp” | Required issuedAt timestamp string. A with clock assumptions stated. |
| SIWX-INFO-06 | RS | MAY | SX:169, “statement … Optional” | Statement optional string; message construction must support absence. A/local CL fixtures. |
| SIWX-INFO-07 | RS | MAY | SX:170, “Default: 5 minutes from issuedAt” | expirationTime optional timestamp; document default versus configured age window. A. |
| SIWX-INFO-08 | RS | MAY | SX:171, “notBefore … Optional” | Optional notBefore timestamp. A. |
| SIWX-INFO-09 | RS | MAY | SX:172, “requestId … Optional” | Optional requestId string. A. |
| SIWX-INFO-10 | RS | MAY | SX:173, “resources … Optional” | Optional URI string array. A. No mandatory one-element list or same-origin restriction. |
| SIWX-CHAIN-01 | RS | MUST (schema) | SX:181, “chainId … CAIP-2” | Each supportedChains entry has string chainId. A. |
| SIWX-CHAIN-02 | RS | MUST (schema) | SX:182, “eip191 for EVM, ed25519 for Solana” | Each supported chain entry declares corresponding type. A for advertised known chain families. |
| SIWX-CHAIN-03 | RS | MAY | SX:183, “signatureScheme … Optional” | Optional signing-UX hint; not a replacement for type. A. |
| SIWX-CHAIN-04 | CL | MUST (prose) | SX:120,185, “first … matches” | Select first supported chain matching wallet. N/tool selection fixtures. |
| SIWX-CHAIN-05 | RS | MUST (prose) | SX:120, “same nonce is shared across all chains” | One challenge nonce spans its advertised chains. A structural; consumption state N/local fixture. |
| SIWX-PROOF-01 | CL/RS | MUST (prose) | SX:126, “SIGN-IN-WITH-X … base64-encoded JSON” | Proof uses that header and encoding. A local no-funds identity fixture or B configured returning-user scenario. |
| SIWX-PROOF-02 | CL | MUST (prose) | SX:191, “echoes all server fields” | Preserve challenge metadata and selected chain/type in client proof. N/tool fixtures. |
| SIWX-PROOF-03 | CL | MUST (schema) | SX:195, “address … Required” | Proof includes signer address, EVM checksummed or Solana Base58. N/local fixtures. |
| SIWX-PROOF-04 | CL | MUST (schema) | SX:196, “signature … Required” | Proof includes signature in specified chain encoding. N/local fixtures. |
| SIWX-MESSAGE-01 | CL/RS | MUST (prose) | SX:204-206, “Message Format: EIP-4361” | EVM signs/verifies SIWE using EIP-191 or stated smart-wallet verification. N/B; full EIP-4361 grammar is not reproduced by this snapshot. |
| SIWX-MESSAGE-02 | CL/RS | MUST (prose) | SX:211-213, “Message Format: Sign-In With Solana” | Solana signs/verifies SIWS with Ed25519. N/B when selected; external message-format dependency must be pinned before claiming complete validation. |
| SIWX-VERIFY-01 | RS | MUST (prose) | SX:264, “Base64 decode … JSON parse” | Parse proof header as specified. A controlled no-funds fixture. |
| SIWX-VERIFY-02 | RS | MUST | SX:268, “configured public origin host exactly” | Expected domain comes from configuration. N for origin source; local fixture can check behavior with known configuration. |
| SIWX-VERIFY-03 | RS | MUST | SX:269, “scheme, host, and port” | URI origin equals configured public origin. N/local fixture; lexical string prefix is not that relation. |
| SIWX-VERIFY-04 | RS | MUST | SX:270, “MUST be recent … MUST NOT be in the future” | Validate issuedAt using configured maximum age and clock. A local clock-controlled fixture; public clock skew makes near-boundary observations inconclusive. |
| SIWX-VERIFY-05 | RS | MUST (conditional) | SX:271, “MUST be in the future” | Present expirationTime must be future. A controlled temporal fixture. |
| SIWX-VERIFY-06 | RS | MUST (conditional) | SX:272, “MUST be in the past” | Present notBefore must be past. A controlled temporal fixture; equality boundary is not clarified. |
| SIWX-VERIFY-07 | RS | MUST | SX:273,316, “MUST be unique”; “Each challenge MUST” | Unique challenge nonce. A can observe sample uniqueness; no finite sample proves generation guarantees. |
| SIWX-VERIFY-08 | RS | SHOULD | SX:273, “SHOULD track used nonces” | Used-nonce tracking is recommended explicitly. N/local state fixture; don't relabel the storage recommendation as uppercase MUST. |
| SIWX-VERIFY-09 | RS | SHOULD | SX:275-288, “SHOULD be reported … machine-readable code” | Report failed field check with machine-readable code; listed codes are recommendation-level. A local fixture. Human text need not match an earlier implementation. |
| SIWX-VERIFY-10 | RS | MUST (prose) | SX:292-295, “Route verification by chainId prefix” | Reconstruct and verify using the selected chain's mechanism. N for implementation; B only demonstrates the selected wallet class. |
| SIWX-VERIFY-11 | RS | SHOULD | SX:297-305, “SHOULD … machine-readable code” | Signature/chain/verifier failures have recommended machine-readable codes. A local fixture. |
| SIWX-HISTORY-01 | RS | MUST (prose) | SX:309, “checks whether … previously paid … application-specific” | After valid identity, apply configured paid-resource entitlement logic. B or C with declared application fixture; no fixed pass semantics are specified. |
| SIWX-CLIENT-01 | CL | MUST | SX:315, “MUST refuse to sign … final URL after redirects” | Client compares challenge domain and URI origin with the final resource origin before signing. N/tool fixtures. |
| SIWX-CLIENT-02 | CL/RS | MAY | SX:315, “resources … MAY be cross-origin” | Associated resources need not match the origin. A/local interoperability fixture; do not reject on this invented restriction. |

## Offer and receipt

Extension support, signed-offer availability, signed-receipt emission, signature validity, and authority to sign for a service are separate outcomes. Unknown authorization policy gives `cannot-assess` for authorization even if cryptographic verification passes. A core PAYMENT-RESPONSE is not the signed receipt artifact of this extension.

| ID | Role | Level | Source and quoted clause | Requirement and evidence |
| --- | --- | --- | --- | --- |
| OFFER-STATUS-01 | RS | MAY | OR:20, “optional, composable addition” | Extension optional; absence is not core nonconformance. A/B. |
| OFFER-STATUS-02 | RS/CL/V | MUST | OR:24-25, “Behavioral requirements … MUST be implemented as written” | Pin normative payload/signature/verification rules despite unstable placement. A/B local artifact validation. |
| OFFER-STATUS-03 | CL/V | SHOULD | OR:26, “unknown extension-specific fields as unsupported” | Do not invent interpretation of unknown extension fields. N/local validator policy; unknown does not automatically mean malformed core message. |
| OFFER-SHAPE-01 | RS | MUST | OR:39-43, “format … eip712 or jws” | Artifact format is one listed string. A for offers; B/C for emitted receipts. |
| OFFER-SHAPE-02 | RS | MUST (conditional) | OR:44,53, “payload is REQUIRED” | EIP-712 artifact has canonical payload object. A/B. |
| OFFER-SHAPE-03 | RS | MUST | OR:45,54, “65 bytes: r+s+v” | Signature required; EIP-712 uses 0x-prefixed 65-byte hex. A/B. |
| OFFER-SHAPE-04 | RS | MUST (disputed scope) | OR:55, “network MUST be eip155 … payTo … EVM address” | Literal EVM-only rule conflicts with chain-agnostic rationale. See A08; do not silently decide this for non-EVM artifacts. A/B. |
| OFFER-SHAPE-05 | RS | MUST NOT | OR:58, “payload MUST be omitted” | JWS artifact has no duplicate payload field. A/B. |
| OFFER-SHAPE-06 | RS | MUST (prose) | OR:59, “JWS Compact Serialization” | JWS signature field has compact header.payload.signature form. A/B; structural decoding is not signature verification. |
| OFFER-DOMAIN-01 | RS/V | MUST (prose) | OR:65-79, “chainId … hardcoded to 1” | EIP-712 domain uses artifact-specific name, version "1", chainId1 irrespective of EVM payment chain. A/B cryptographic checks. |
| OFFER-SCHEMA-01 | RS | MUST NOT | OR:89, “MUST NOT be included … transmitted” | Do not transmit canonical types or primaryType inside artifacts. A/B. |
| OFFER-SCHEMA-02 | RS | MUST | OR:90, “Signers MUST use … canonical” | Sign with spec canonical types/primaryType. A/B verifies against pinned schema. |
| OFFER-SCHEMA-03 | V | MUST | OR:91, “Verifiers MUST obtain and use” | Verifier supplies pinned canonical schema itself. N/tool fixtures. |
| OFFER-SCHEMA-04 | M | MUST | OR:92, “MUST be accompanied by explicit versioning” | Schema changes require versioning. N/document version audit. |
| OFFER-JWS-01 | RS | MUST | OR:100-104, “header MUST include … alg” | JWS protected header includes signing algorithm string. A/B. Example algorithms are not a compulsory support list. |
| OFFER-JWS-02 | RS | MUST | OR:100,105, “kid … DID URL” | JWS header includes key identifier string in specified form. A/B; resolving/authorizing it requires configured supported method. |
| OFFER-PLACE-01 | RS | MUST (prose/profile) | OR:114-120, “info.offers array … corresponds to … accepts” | Signed offers live at current pinned offer-receipt.info.offers and correspond to payment entries. A. Does not explicitly require every accepts entry to have a signed offer. |
| OFFER-MATCH-01 | RS | SHOULD | OR:120, “SHOULD maintain the same ordering” | Matching array order recommended, not mandatory. A. |
| OFFER-MATCH-02 | CL/V | MUST | OR:120, “MUST match … by comparing payload fields” | Match signed terms, not index position. N/tool fixtures using supplied offers. |
| OFFER-INDEX-01 | RS | SHOULD | OR:126, “SHOULD include acceptIndex” | Unsigned convenience index recommended. A. Omission is not MUST failure. |
| OFFER-INDEX-02 | CL/V | MUST NOT | OR:126,134, “MUST NOT … authoritative” | Index does not establish artifact integrity/binding. N/tool fixtures. |
| OFFER-INDEX-03 | CL | SHOULD | OR:130-132, “Check … in-range”; “terms match” | Validate index range and cross-check signed fields when supplied. N/tool fixtures. |
| OFFER-INDEX-04 | V | MAY/SHOULD | OR:138, “MAY be omitted”; “SHOULD ignore” | External artifacts may omit index; external verifiers ignore index without negotiation context. N/local fixtures. |
| OFFER-PAYLOAD-01 | RS | MUST (schema) | OR:146, “version … currently 1” | Offer payload requires version1. A. |
| OFFER-PAYLOAD-02 | RS | MUST (schema) | OR:147, “resourceUrl … Yes” | Offer requires paid resource URL string. A. |
| OFFER-PAYLOAD-03 | RS | MUST (schema) | OR:148, “scheme … Yes” | Offer requires scheme string. A. |
| OFFER-PAYLOAD-04 | RS | MUST (schema) | OR:149, “network … CAIP-2” | Offer requires network string. A. |
| OFFER-PAYLOAD-05 | RS | MUST (schema) | OR:150, “asset … Yes” | Offer requires asset string. A. |
| OFFER-PAYLOAD-06 | RS | MUST (schema) | OR:151, “payTo … Yes” | Offer requires recipient string. A. |
| OFFER-PAYLOAD-07 | RS | MUST (schema) | OR:152, “amount … string … Yes” | Offer requires amount string. A; match exact units rather than display currency. |
| OFFER-PAYLOAD-08 | RS | MAY | OR:153, “validUntil … Optional” | Optional Unix-second expiration number. A; EIP-712 zero convention separately mandatory. |
| OFFER-TYPES-01 | RS/V | MUST | OR:159-184, “Normative Schema”; “unused … 0” | Use Offer primaryType and ordered fields from §4.3; absent validity encoded0 and interpreted as absent. A/local cryptographic check. |
| OFFER-VERIFY-01 | V | MUST | OR:223, “used exactly as transmitted” | Verify transmitted offer payload; do not reconstruct from surrounding x402 context. N/tool fixtures. |
| OFFER-VERIFY-02 | V | MUST (prose) | OR:224-233, “Verify … complete payload” | Verify appropriate EIP-712/JWS signature and interpret supported payload version. A artifact verification, with explicit unsupported-algorithm outcome. |
| OFFER-AUTH-01 | V | MUST | OR:237, “distinguish … validity and signer authorization” | Separate cryptographic result from service authorization. A/B plus trust configuration; missing evidence is cannot-assess. |
| OFFER-AUTH-02 | V | MUST | OR:241, “MUST confirm … authorized” | Confirm key authority for resourceUrl with a declared method. No single DNS/DID/registry scheme is mandatory. A/B plus policy; do not require signer=payTo universally. |
| OFFER-AUTH-03 | RS | SHOULD | OR:243, “dedicated signing key separate from payTo” | Dedicated signing key recommended. A if identity known; not grounds to reject other supported authorization methods. |
| OFFER-AUTH-04 | RS/V | SHOULD (conditional) | OR:245, “SHOULD enable DNSSEC … validate … when available” | DNS-based authorization has DNSSEC recommendations. N without selected DNS profile. |
| OFFER-AUTH-05 | V | SHOULD | OR:248, “temporally immutable authorization evidence” | Historical verification preserves issuance-time authorization evidence across rotations. N without that evidence. |
| OFFER-EXPIRY-01 | RS | MAY | OR:252-258, “MAY reject”; “enforcement decision rests” | Expired offer rejection is permitted, not required. A/B observational; no universal fail on acceptance. |
| OFFER-EXPIRY-02 | CL | SHOULD | OR:258, “SHOULD check expiration before paying” | Check expiry before payment. N/tool fixtures. |
| RECEIPT-EMIT-01 | RS | MUST (prose) | OR:263, “only on success … payment … service … delivered” | Signed receipt asserts both payment and delivery success. B/C. Unlike core settlement receipt, it is not a failure diagnostic. |
| RECEIPT-EMIT-02 | RS | MAY | OR:267, “MAY include a receipt” | Even successful settlement need not include this signed receipt. B/C absence is allowed. |
| RECEIPT-PLACE-01 | RS | MUST (prose/profile) | OR:267-270, “extensions … info.receipt” | Emitted signed receipt uses current pinned placement inside SettlementResponse.extensions. B/C. |
| RECEIPT-PAYLOAD-01 | RS | MUST (schema) | OR:283, “version … currently 1” | Required receipt payload version1. B/C. |
| RECEIPT-PAYLOAD-02 | RS | MUST (schema) | OR:284, “network … CAIP-2” | Required network string. B/C. |
| RECEIPT-PAYLOAD-03 | RS | MUST (schema) | OR:285, “resourceUrl … Yes” | Required paid resource URL string. B/C. |
| RECEIPT-PAYLOAD-04 | RS | MUST (schema) | OR:286, “payer … Yes” | Required payer identifier string for this artifact, although core receipt payer is optional. B/C. |
| RECEIPT-PAYLOAD-05 | RS | MUST (schema) | OR:287, “issuedAt … Unix timestamp (seconds)” | Required issuance timestamp number. B/C. |
| RECEIPT-PAYLOAD-06 | RS | MAY | OR:288-290, “transaction … Optional” | Signed artifact transaction optional; core SettlementResponse transaction has different requiredness. B/C. |
| RECEIPT-TYPES-01 | RS/V | MUST | OR:296-319, “Normative Schema”; “empty string” | Use Receipt schema from §5.3; unused transaction signs empty string and verifies as absence. B/C local cryptographic check. |
| RECEIPT-VERIFY-01 | V | MUST | OR:371, “used exactly as transmitted” | Do not infer receipt fields from outer payment response. N/tool fixtures. |
| RECEIPT-VERIFY-02 | V | MUST (prose) | OR:372-384, “Verify … Confirm … authorized” | Verify signature/version, service authority, and issuedAt under declared verifier policy. B/C artifact check plus authorization configuration. |
| RECEIPT-VERIFY-03 | V | MAY | OR:375,385, “MAY check the blockchain” | Transaction lookup is optional for signed-artifact verification; payment E2E ledger evidence is a separate check. B. |
| RECEIPT-AUTH-01 | V | SHOULD | OR:387, “as of … issuedAt” | Historical receipt authorization evaluated at issuance; later revocation alone is not proof of historical invalidity. N without historical policy/evidence. |
| ARTIFACT-CANON-01 | RS/V | MUST | OR:870, “JCS for JWS … EIP-712 rules” | Apply specified canonicalization. A/B cryptographic fixtures; JCS normative dependency must be pinned separately. |
| ARTIFACT-CANON-02 | RS | MUST NOT | OR:871, “signature field in the payload being signed” | Signature is not circularly included in signed payload. A/B. |

## Ambiguities and limits that need explicit decisions

These are specification observations, not target findings. A checker should retain an ambiguity identifier in evidence when its verdict depends on a documented interpretation.

| ID | Source conflict or gap | Conservative handling |
| --- | --- | --- |
| A01 | C:117 requires an array but does not state minItems, although payment flow expects usable requirements. Numeric/amount bounds and global unknown-property rejection are similarly absent. | Separate structural core validity from “no payable offer found”; do not invent a MUST or silently treat an unusable quote as successful E2E. |
| A02 | H error table maps malformed→400, failed→402, internal→500, success→200. It does not specify every backend status, non-terminal settlement policy, or cached replay status. | Name the tested category and interpretation. No mandatory409 on bare payment replay and no mandatory fresh terms on failed-settlement402 without an extension clause. |
| A03 | C:147-150 says extension schema defines info, while SX:48-77 requires address/signature absent from server challenge info. | Use extension-specific validation target: SIWx schema example is for a client proof. Generic “validate every info against schema” would reject the supplied SIWx example. |
| A04 | SX examples use x402Version string "2" (15,90), unlike C:114 numeric2. E Permit2 example is not valid JSON; examples contain shortened signatures and placeholders. | Prefer normative field tables; fix/label illustrative examples before using as positive test vectors. Never assert their cryptographic validity. |
| A05 | Bazaar sidechannel table BZ:479 says “402 response body”, but H:14-15,172-174 and C:74 make PAYMENT-REQUIRED canonical and body implementation-specific. | Validate extension inside decoded header, not a mandatory body duplicate. Record stale wording. |
| A06 | PI:85 says same ID/same payload returns cache, but91-107 recommends normalized fingerprint, and119-120 permits RS and/or F consumption. Required=false default also coexists with an example schema requiring the field. | Select consumer role and payload-equivalence policy; do not demand application-response caching from RS based on forwarding-only support. Omitted info.required should be treated as documented default, with example divergence noted. |
| A07 | E:189 names permit2Authorization.amount, while example uses permitted.amount; “covers” must coexist with X:39 exact transfer. Example proxy has its own detailed behavior. | Use structural payment authorization plus exact transfer semantics; flag field-path inconsistency. Do not infer permission to overcharge. |
| A08 | OR:55 restricts EIP-712 network/payTo to EVM, but79 and version-history887 explicitly describe chain-agnostic signing, including non-EVM networks; receipt payload has no payTo at all. | EVM artifact profile is unambiguous; mark broader interpretation unresolved rather than failing all non-EVM signed artifacts or requiring receipt.payTo. |
| A09 | OR:24 calls placement unstable while25 makes behavioral requirements normative. | Pin exact revision/placement profile in reports. “Latest compatible” is not a reproducible conformance target. |
| A10 | C list example uses items (521); BZ:451 says search uses resources and “mirrors” list. List top-level required fields are example-based, whereas item fields have a Required table. | Separate list/search parsers and label assumed envelope profile; do not silently rewrite item fields or pretend one envelope is unambiguously mandated everywhere. |
| A11 | BZ body field table267 allows object/string; POST example137 object-only. BZ output example292 allows any; examples often object-only. Dynamic pathParams also absent from early additionalProperties=false examples. | Tables/prose define profile; validate actual advertised schema and info compatibility, not a copied generic example schema. |
| A12 | BZ321 permits same-document JSON Pointer fragments “starting with #”, but not every #fragment is a JSON Pointer. routeTemplate regex573 and nonempty-rule wording also differ on a bare slash. | Implement a named/documented literal interpretation; mark questionable edge cases cannot-assess pending clarification. |
| A13 | E binding has no explicit per-ATM flow table or all declarations demanded by X:30-35. | Do not fill mechanism-document gaps from the target's implementation. Record exact default/upfront support assumptions and cannot-assess where binding is missing. |
| A14 | SX273 has MUST uniqueness and SHOULD used-nonce tracking; defaults/temporal equality/skew are incompletely specified. Error-table descriptions279-280 use request-host/prefix wording despite stronger configured-origin exact-match prose268-269,315. | Preserve levels; use strongest explicit configured-origin clause; declare clock/age policy. Do not require a particular nonce store or free-text error. |
| A15 | EIP-712/SIWE/CAIP-2/JCS/JSON Schema/Permit2 and optional gas-sponsoring details rely on external documents not copied here. | Pin those dependencies before claiming full validation. Structural checks or a library's acceptance alone are narrower evidence. |
| A16 | Service metadata core tables constrain emitted fields, while Bazaar extraction deliberately soft-drops malformed fields and preserves the rest. | Distinguish RS declaration failure from CL/F sanitization behavior. Do not turn a consumer sanitation rule into mandatory rejection of the whole payment. |
| A17 | Some security/example network paragraphs use older names such as maxAmountRequired (X:66) alongside v2 amount. | Scope by network binding/version; do not add legacy fields to v2 generic schemas. |
| A18 | Core includes no configured one-hour pass, custom settlement-state header, token issuance mechanism, or GET purchase-status endpoint. | Keep target-specific adapters and operational UX outside the normative core score; no prior implementation's contract may fill a spec gap. |

## Evidence and reporting recommendations

These recommendations are tool design choices, not new x402 requirements:

1. A report states snapshot, role, profile, capability applicability, execution mode and observed evidence. “Core structure passed” is not “x402 implementation fully conformant”.
2. `pass` needs positive evidence for the clause; `fail` needs a contradictory observation under satisfied prerequisites; `skip` means not applicable or intentionally not selected; `cannot-assess` names missing observability, unsupported checker or ambiguous oracle. Recommendation violations should not become mandatory-conformance failures.
3. A testnet payment report separates quote validation, proof construction, transport response, settlement receipt, independent ledger confirmation and resource outcome. None substitutes for another.
4. C is a local, explicitly configured integration fixture, with benign test payloads and no actual settlement. It validates RS interaction under scripted F outcomes. It does not certify an external facilitator or constitute a production failure reproduction.
5. Ordering assertions require a backend witness, not response timing. Side effects, logs and trace identities must belong to the same run. No witness means cannot-assess for ordering, even when HTTP/status assertions pass.
6. Capability omissions and unsupported tool mechanisms remain visible in the denominator. Do not emit a green “all compliant” summary when applicable mandatory checks are unassessed.
7. Copy spec examples only after separating placeholders, JSON syntax errors, illustrative values, schema inconsistencies and actual independently valid signed vectors. Negative/local validator fixtures should exercise one declared contract at a time.
