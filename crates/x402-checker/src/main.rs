//! Command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use anyhow::{Context as _, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use jiff::Timestamp;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Method, Url};
use x402_checker::check::SuiteResult;
use x402_checker::render::{self, Color};
use x402_checker::report::Report;
use x402_checker::suites::ledger::{Expected, LedgerOptions};
use x402_checker::suites::pay::PayOptions;
use x402_checker::suites::scenarios::{MechanismKind, ScenarioOptions};
use x402_checker::suites::{ledger, pay, probe, scenarios};
use x402_checker::target::{Context, Options, Target};
use x402_checker_evm::Payer;
use x402_checker_testbed::{Facilitator, FacilitatorConfig, Recorder, Script, Witness, WitnessScript};

/// Checks an x402 v2 resource server against the specification.
///
/// Every verdict names the requirement id and the clause behind it (docs/requirements.md). The outcome only
/// covers the executed scope: `probe` certifies neither a payment nor a call order.
#[derive(Debug, Parser)]
#[command(name = "x402-checker", version, about, long_about = None, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Checks the 402 signal and its terms. Needs no funds and no cooperation from the server.
    Probe(TargetArgs),
    /// Sends one reference payment on a test network with the given key, then a replay, an expired and a
    /// not-yet-valid authorization. The reference payment is settled for real (the price of one call) when the
    /// server and its facilitator accept it; `--spendable-negatives` adds two more signed authorizations.
    Pay(PayArgs),
    /// Runs probe, then pay when a key is given (scenarios is separate: it needs the server reconfigured).
    All(PayArgs),
    /// Hosts a scripted facilitator (and a witness backend) that the server must be configured to use, then
    /// drives every settlement outcome through the server. Needs no funds. The tool first reads the server's 402
    /// to learn which networks to advertise, then starts the doubles and prints their URLs.
    Scenarios(ScenarioArgs),
    /// Hosts the scripted facilitator and the witness backend for a manual session, until Ctrl-C.
    Serve(ServeArgs),
    /// Reads the chain for a settlement already made: the transaction of a receipt against the offer it paid.
    /// The same checks `pay` runs after its payment, without paying again. Always strict: a transfer or a
    /// binding that is not demonstrated makes the result incomplete (exit code 2), so pass --nonce when known.
    Ledger(LedgerArgs),
}

/// The resource to exercise.
#[derive(Debug, Args)]
struct TargetArgs {
    /// URL of the protected resource.
    url: Url,
    /// HTTP method the resource expects.
    #[arg(short = 'X', long, default_value = "GET")]
    method: Method,
    /// Extra request header, `Name: value`; repeatable.
    #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,
    /// Request body for methods that take one.
    #[arg(short = 'd', long, value_name = "TEXT")]
    body: Option<String>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    /// Refuse an incomplete run: exit 2 (Incomplete) when required checks were not demonstrated in this scope.
    #[arg(long)]
    strict: bool,
}

/// The paying wallet and its limits.
#[derive(Debug, Args)]
struct PayArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// Private key of the paying wallet, `0x`-prefixed hex. Prefer the environment variable, set without typing
    /// the key on a command line (a secret store, `read -rs`): a flag or an inline assignment ends up in the shell
    /// history. Test wallets only.
    #[arg(long, env = "X402_PAYER_KEY", hide_env_values = true, value_name = "HEX")]
    payer_key: Option<String>,
    /// Pay on networks the tool does not know as testnets.
    #[arg(long)]
    allow_mainnet: bool,
    /// Validity of the signed authorization, in seconds.
    #[arg(long, default_value_t = 300)]
    validity: u64,
    /// Refuse to pay an offer above this many atomic units of the asset.
    #[arg(long, value_name = "ATOMIC")]
    max_amount: Option<U256>,
    /// Also send the wrong-value and wrong-recipient authorizations. They are refused by a conformant server,
    /// but anyone who sees them could submit them on chain: test wallets only.
    #[arg(long)]
    spendable_negatives: bool,
    #[command(flatten)]
    chain: ChainArgs,
    /// Do not read the chain after the payment; the transfer is then reported as not established.
    #[arg(long)]
    no_ledger: bool,
}

/// How the chain is read.
#[derive(Debug, Args)]
struct ChainArgs {
    /// JSON-RPC endpoint of the paid network. Default: a public node of the test network.
    #[arg(long, env = "X402_RPC_URL", value_name = "URL")]
    rpc_url: Option<Url>,
    /// Seconds to wait for the node to know the transaction, requests included.
    #[arg(long, default_value_t = 60, value_name = "SECONDS")]
    ledger_wait: u64,
}

impl ChainArgs {
    fn options(&self) -> LedgerOptions {
        LedgerOptions {
            rpc_url: self.rpc_url.clone(),
            wait: Duration::from_secs(self.ledger_wait),
        }
    }
}

/// A settlement to read on chain.
#[derive(Debug, Args)]
struct LedgerArgs {
    /// Transaction hash from the receipt.
    #[arg(value_name = "TX_HASH")]
    transaction: String,
    /// Network of the offer (CAIP-2, EVM only).
    #[arg(long, default_value = "eip155:84532", value_name = "CAIP-2")]
    network: String,
    /// Token contract of the offer.
    #[arg(long, value_name = "ADDRESS")]
    asset: Address,
    /// Recipient of the offer.
    #[arg(long, value_name = "ADDRESS")]
    pay_to: Address,
    /// Amount of the offer, atomic units.
    #[arg(long, value_name = "ATOMIC")]
    amount: U256,
    /// The paying wallet.
    #[arg(long, value_name = "ADDRESS")]
    payer: Address,
    /// Nonce of the signed authorization; without it the binding check is skipped.
    #[arg(long, value_name = "HEX32")]
    nonce: Option<B256>,
    #[command(flatten)]
    chain: ChainArgs,
}

/// The doubles the tool hosts.
#[derive(Debug, Args)]
struct DoublesArgs {
    /// Address the scripted facilitator listens on.
    #[arg(long, default_value = "127.0.0.1:4020", value_name = "HOST:PORT")]
    facilitator_listen: std::net::SocketAddr,
    /// Address the witness backend listens on; omit to run without a witness.
    #[arg(long, value_name = "HOST:PORT")]
    witness_listen: Option<std::net::SocketAddr>,
    /// Signer address the facilitator advertises in /supported for eip155 networks.
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000402",
        value_name = "ADDRESS"
    )]
    facilitator_signer: String,
    /// Fee payer (base58) the facilitator advertises in /supported for solana networks.
    #[arg(long, default_value = x402_checker_testbed::DEFAULT_SVM_FEE_PAYER, value_name = "ADDRESS")]
    facilitator_fee_payer: String,
    /// URL under which the server reaches the facilitator, when it differs from the listen address (a container,
    /// a tunnel, another host). Printed for the operator; the tool itself does not use it.
    #[arg(long, value_name = "URL")]
    facilitator_public_url: Option<Url>,
    /// URL under which the server reaches the witness, when it differs from the listen address.
    #[arg(long, value_name = "URL")]
    witness_public_url: Option<Url>,
}

/// The scenarios run.
#[derive(Debug, Args)]
struct ScenarioArgs {
    #[command(flatten)]
    target: TargetArgs,
    #[command(flatten)]
    doubles: DoublesArgs,
    /// Print the URLs to configure, then wait for Enter before running (time to configure the server).
    #[arg(long)]
    pause: bool,
    /// How long to wait for the server's facilitator calls after each response, in seconds.
    #[arg(long, default_value_t = 5)]
    settle_wait: u64,
    /// Network(s) the facilitator advertises (CAIP-2), repeatable. When given, the doubles start before the server
    /// is contacted, for a server that queries /supported at startup; otherwise the networks are read from its 402.
    #[arg(long = "network", value_name = "CAIP-2")]
    networks: Vec<String>,
    /// The offer family to pay with: `evm` signs EIP-3009 authorizations, `svm` sends transactions made of random
    /// bytes to the server's Solana offer (the scripted facilitator reads none).
    #[arg(long, value_enum, default_value_t = MechanismArg::Evm)]
    mechanism: MechanismArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MechanismArg {
    Evm,
    Svm,
}

impl From<MechanismArg> for MechanismKind {
    fn from(value: MechanismArg) -> Self {
        match value {
            MechanismArg::Evm => Self::Evm,
            MechanismArg::Svm => Self::Svm,
        }
    }
}

/// A manual session.
#[derive(Debug, Args)]
struct ServeArgs {
    #[command(flatten)]
    doubles: DoublesArgs,
    /// Network(s) the facilitator advertises in /supported (CAIP-2), repeatable.
    #[arg(long = "network", default_value = "eip155:84532", value_name = "CAIP-2")]
    networks: Vec<String>,
}

/// How to report.
#[derive(Debug, Args)]
struct OutputArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,
    /// Write the report to this file instead of stdout.
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,
    /// Print every exchange, not only those a failure points at.
    #[arg(short, long, global = true)]
    verbose: bool,
    /// Colour policy for text output.
    #[arg(long, value_enum, default_value_t = ColorArg::Auto, global = true)]
    color: ColorArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable, coloured on a terminal.
    Text,
    /// The full report, findings and exchanges, for CI and diffing.
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorArg {
    Auto,
    Always,
    Never,
}

impl From<ColorArg> for Color {
    fn from(value: ColorArg) -> Self {
        match value {
            ColorArg::Auto => Self::Auto,
            ColorArg::Always => Self::Always,
            ColorArg::Never => Self::Never,
        }
    }
}

impl TargetArgs {
    fn target(&self) -> Result<Target> {
        let mut headers = Vec::new();
        for raw in &self.headers {
            let (name, value) = raw
                .split_once(':')
                .with_context(|| format!("header {raw:?} is not `Name: value`"))?;
            headers.push((
                HeaderName::from_bytes(name.trim().as_bytes())
                    .with_context(|| format!("invalid header name in {raw:?}"))?,
                HeaderValue::from_str(value.trim())
                    .with_context(|| format!("invalid header value in {raw:?}"))?,
            ));
        }
        if !matches!(self.url.scheme(), "http" | "https") {
            bail!("the target URL must be http or https, got {}", self.url.scheme());
        }
        Ok(Target {
            url: self.url.clone(),
            method: self.method.clone(),
            headers,
            body: self.body.clone(),
        })
    }

    fn context(&self, allow_mainnet: bool) -> Result<Context> {
        let options = Options {
            allow_mainnet,
            timeout: Duration::from_secs(self.timeout),
        };
        Context::new(self.target()?, options).context("building the HTTP client")
    }
}

impl PayArgs {
    fn options(&self) -> Result<Option<PayOptions>> {
        let Some(key) = &self.payer_key else {
            return Ok(None);
        };
        let payer = Payer::from_private_key(key)
            .context("the payer key is not a 0x-prefixed 32-byte hex private key")?;
        Ok(Some(PayOptions {
            payer,
            allow_mainnet: self.allow_mainnet,
            validity: self.validity,
            max_amount: self.max_amount,
            spendable_negatives: self.spendable_negatives,
            ledger: (!self.no_ledger).then(|| self.chain.options()),
        }))
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(2)),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

impl DoublesArgs {
    async fn spawn(&self, networks: &[String]) -> Result<(Facilitator, Option<Witness>)> {
        let recorder = Recorder::new();
        let config =
            FacilitatorConfig::exact(networks, &self.facilitator_signer, &self.facilitator_fee_payer);
        let facilitator = Facilitator::spawn(
            self.facilitator_listen,
            config,
            Script::default(),
            recorder.clone(),
        )
        .await
        .with_context(|| format!("binding the facilitator on {}", self.facilitator_listen))?;
        let witness = match self.witness_listen {
            Some(listen) => Some(
                Witness::spawn(listen, WitnessScript::default(), recorder)
                    .await
                    .with_context(|| format!("binding the witness on {listen}"))?,
            ),
            None => None,
        };
        let shown = |listen: String, public: &Option<Url>| match public {
            Some(url) => format!("{url} (listening on {listen})"),
            None => format!(
                "{listen} (pass --facilitator-public-url / --witness-public-url if the server reaches this host differently)"
            ),
        };
        eprintln!(
            "configure the server's facilitator as: {}",
            shown(facilitator.url(), &self.facilitator_public_url)
        );
        match &witness {
            Some(w) => eprintln!(
                "configure the server's upstream as:    {}",
                shown(w.url(), &self.witness_public_url)
            ),
            None => {
                eprintln!("witness backend not started: pass --witness-listen to observe the resource call");
            }
        }
        Ok((facilitator, witness))
    }
}

async fn serve(args: &ServeArgs, output: &OutputArgs) -> Result<i32> {
    use std::fmt::Write as _;
    let (facilitator, _witness) = args.doubles.spawn(&args.networks).await?;
    eprintln!("Ctrl-C stops and prints the calls seen");
    tokio::signal::ctrl_c().await.context("waiting for Ctrl-C")?;
    let calls = facilitator.recorder().calls();
    let rendered = match output.format {
        Format::Json => serde_json::to_string_pretty(&calls).context("serialising the calls")?,
        Format::Text => calls.iter().fold(String::new(), |mut text, c| {
            let _ = writeln!(
                text,
                "#{} {:?} {} {} -> {:?}",
                c.seq, c.endpoint, c.method, c.path, c.answered_status
            );
            text
        }),
    };
    write_output(output, &rendered)?;
    Ok(0)
}

async fn read_ledger(args: &LedgerArgs, output: &OutputArgs, started: Timestamp) -> Result<i32> {
    let chain_id = args
        .network
        .parse::<x402_checker_types::Caip2>()
        .ok()
        .and_then(|n| n.evm_chain_id())
        .with_context(|| format!("{} is not an eip155 network", args.network))?;
    let expected = Expected {
        chain_id,
        asset: args.asset,
        pay_to: args.pay_to,
        amount: args.amount,
        payer: args.payer,
        nonce: args.nonce,
    };
    let verified = ledger::verify(
        &expected,
        &args.transaction,
        None,
        Some(&args.chain.options()),
        &[],
    )
    .await;
    let suite = SuiteResult {
        ledger: verified.snapshot.into_iter().collect(),
        ..SuiteResult::new("ledger", verified.findings)
    };
    let report = Report::build(
        format!("{} {}", args.network, args.transaction),
        started,
        true,
        vec![suite],
        Vec::new(),
        Vec::new(),
    );
    emit(&report, output)
}

fn emit(report: &Report, output: &OutputArgs) -> Result<i32> {
    let rendered = match output.format {
        Format::Text => render::text(
            report,
            render::Options {
                verbose: output.verbose,
                color: output.color.into(),
            },
        ),
        Format::Json => report.to_json(),
    };
    write_output(output, &rendered)?;
    Ok(report.exit_code)
}

fn write_output(output: &OutputArgs, rendered: &str) -> Result<()> {
    if let Some(path) = &output.output {
        return std::fs::write(path, rendered).with_context(|| format!("writing {}", path.display()));
    }
    print!("{rendered}");
    Ok(())
}

async fn run(cli: Cli) -> Result<i32> {
    let started = Timestamp::now();
    if let Command::Serve(args) = &cli.command {
        return serve(args, &cli.output).await;
    }
    if let Command::Ledger(args) = &cli.command {
        return read_ledger(args, &cli.output, started).await;
    }
    let mut omitted: Vec<String> = Vec::new();
    let (target_args, suites, ctx) = match &cli.command {
        Command::Probe(args) => {
            let mut ctx = args.context(false)?;
            let suites = vec![probe::run(&mut ctx).await];
            (args, suites, ctx)
        }
        Command::Pay(args) => {
            let Some(options) = args.options()? else {
                bail!("`pay` needs a payer key: set X402_PAYER_KEY or pass --payer-key");
            };
            let mut ctx = args.target.context(args.allow_mainnet)?;
            let suites = vec![pay::run(&mut ctx, &options).await];
            (&args.target, suites, ctx)
        }
        Command::All(args) => {
            let mut ctx = args.target.context(args.allow_mainnet)?;
            let mut suites: Vec<SuiteResult> = vec![probe::run(&mut ctx).await];
            if let Some(options) = args.options()? {
                suites.push(pay::run(&mut ctx, &options).await);
            } else {
                omitted.push("pay (no payer key: set X402_PAYER_KEY or pass --payer-key)".to_owned());
            }
            (&args.target, suites, ctx)
        }
        Command::Scenarios(args) => {
            let mut ctx = args.target.context(false)?;
            // the facilitator advertises what the server offers: from --network, else read from the server's 402
            let networks: Vec<String> = if args.networks.is_empty() {
                let probe_index = ctx
                    .client
                    .send(
                        "terms for the facilitator configuration",
                        ctx.resource_request(&[]),
                    )
                    .await
                    .ok();
                probe_index
                    .and_then(|i| ctx.client.exchange(i).payment_required())
                    .map_or_else(
                        || vec!["eip155:84532".to_owned()],
                        |t| t.accepts.into_iter().map(|o| o.network).collect(),
                    )
            } else {
                args.networks.clone()
            };
            let (facilitator, witness) = args.doubles.spawn(&networks).await?;
            if args.pause {
                eprintln!("press Enter when the server is configured...");
                let mut line = String::new();
                let read = std::io::stdin().read_line(&mut line).context("reading stdin")?;
                if read == 0 {
                    bail!("--pause needs an interactive stdin: end of input reached before Enter");
                }
            }
            let options = ScenarioOptions {
                facilitator,
                witness,
                settle_wait: Duration::from_secs(args.settle_wait),
                mechanism: args.mechanism.into(),
            };
            let suites = vec![scenarios::run(&mut ctx, &options).await];
            (&args.target, suites, ctx)
        }
        Command::Serve(_) | Command::Ledger(_) => unreachable!("handled above"),
    };
    let report = Report::build(
        target_args.url.to_string(),
        started,
        target_args.strict,
        suites,
        omitted,
        ctx.client.into_exchanges(),
    );
    emit(&report, &cli.output)
}
