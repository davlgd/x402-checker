//! Reads an EVM ledger over JSON-RPC, enough to check that a settlement receipt names a transaction that exists,
//! succeeded, and moved the authorized amount of the asset to the recipient.
//!
//! The crate deliberately stays small: two RPC methods (`eth_chainId`, `eth_getTransactionReceipt`), a bounded
//! wait for the receipt, and the two events that matter for `exact` with EIP-3009 (`Transfer` of ERC-20 and
//! `AuthorizationUsed` of EIP-3009). It reads no balances and follows no reorganisations: a receipt returned by the
//! node is taken as the node's word, which is one step further than the facilitator's.

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, LogData, U64, U256};
use alloy_sol_types::{SolEvent, sol};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

sol! {
    /// ERC-20 transfer event, emitted by the asset when value moves.
    event Transfer(address indexed from, address indexed to, uint256 value);
    /// EIP-3009 event, emitted when an authorization is consumed.
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
}

/// Public JSON-RPC endpoints of the test networks the tool pays on, by EVM chain id. Best effort: public nodes
/// rate-limit and change; an operator can always name another endpoint.
pub fn public_rpc(chain_id: u64) -> Option<&'static str> {
    Some(match chain_id {
        84532 => "https://sepolia.base.org",
        11_155_111 => "https://ethereum-sepolia-rpc.publicnode.com",
        43113 => "https://api.avax-test.network/ext/bc/C/rpc",
        80002 => "https://rpc-amoy.polygon.technology",
        421_614 => "https://sepolia-rollup.arbitrum.io/rpc",
        11_155_420 => "https://sepolia.optimism.io",
        97 => "https://bsc-testnet-rpc.publicnode.com",
        59141 => "https://rpc.sepolia.linea.build",
        _ => return None,
    })
}

/// Why the ledger could not be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The endpoint could not be reached or did not answer HTTP.
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),
    /// The endpoint answered a JSON-RPC error.
    #[error("rpc error {code}: {message}")]
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message.
        message: String,
    },
    /// The endpoint answered something that is not the expected shape.
    #[error("unexpected answer: {0}")]
    Shape(String),
}

/// One log entry of a transaction receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    /// Emitting contract.
    pub address: Address,
    /// Indexed topics, the first being the event signature hash.
    pub topics: Vec<B256>,
    /// Non-indexed data.
    pub data: Bytes,
    /// Position in the block; absent from some preconfirmation caches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_index: Option<U64>,
}

/// An ERC-20 transfer decoded from a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Erc20Transfer {
    /// Sender.
    pub from: Address,
    /// Recipient.
    pub to: Address,
    /// Amount in atomic units.
    pub value: U256,
}

/// A transaction receipt, the fields this crate reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    /// Transaction hash.
    pub transaction_hash: B256,
    /// `0x1` on success, `0x0` on revert.
    pub status: U64,
    /// Block that includes the transaction.
    pub block_number: U64,
    /// Hash of that block.
    pub block_hash: B256,
    /// Top-level sender of the transaction, who paid the gas: a facilitator, a relay, anyone; not necessarily the
    /// payer.
    pub from: Address,
    /// Contract or account called; `None` for a contract creation.
    #[serde(default)]
    pub to: Option<Address>,
    /// Logs emitted, in order.
    pub logs: Vec<Log>,
}

impl TransactionReceipt {
    /// Whether the transaction succeeded.
    pub fn succeeded(&self) -> bool {
        self.status == U64::from(1)
    }

    /// Whether the receipt names a sealed block. Some sequencers (Flashblocks-style preconfirmations) answer a
    /// receipt with a zero block hash before the block exists; such a receipt is a promise, not an inclusion.
    pub fn is_sealed(&self) -> bool {
        !self.block_hash.is_zero()
    }

    /// The ERC-20 `Transfer` events emitted by `asset`, in order.
    pub fn transfers(&self, asset: Address) -> Vec<Erc20Transfer> {
        self.decode::<Transfer>(asset)
            .map(|event| Erc20Transfer {
                from: event.from,
                to: event.to,
                value: event.value,
            })
            .collect()
    }

    /// The `(authorizer, nonce)` pairs of the EIP-3009 `AuthorizationUsed` events emitted by `asset`.
    pub fn authorizations_used(&self, asset: Address) -> Vec<(Address, B256)> {
        self.decode::<AuthorizationUsed>(asset)
            .map(|event| (event.authorizer, event.nonce))
            .collect()
    }

    fn decode<E: SolEvent>(&self, asset: Address) -> impl Iterator<Item = E> + '_ {
        self.logs
            .iter()
            .filter(move |log| log.address == asset)
            .filter_map(|log| {
                let data = LogData::new(log.topics.clone(), log.data.clone())?;
                E::decode_log_data(&data).ok()
            })
    }
}

/// What waiting for a receipt ended with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wait {
    /// The node returned a receipt in a sealed block.
    Sealed(TransactionReceipt),
    /// The node only ever returned a receipt with a zero block hash: a preconfirmation, no sealed block yet.
    Preconfirmed(TransactionReceipt),
    /// The node answered `null` to every poll: no inclusion receipt from it, whether the transaction is pending,
    /// dropped or unknown to it.
    Unknown {
        /// Number of `null` answers.
        polls: u32,
    },
    /// No complete answer arrived before the deadline (after `polls` answered ones, all `null`).
    Unanswered {
        /// Number of answered polls before the one that did not finish.
        polls: u32,
    },
}

/// A JSON-RPC client bound to one endpoint.
#[derive(Debug, Clone)]
pub struct Ledger {
    http: reqwest::Client,
    url: Url,
}

impl Ledger {
    /// A client for `url`; each request times out after 20 seconds unless the caller bounds it tighter.
    pub fn new(url: Url) -> Result<Self, Error> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()?,
            url,
        })
    }

    /// The endpoint.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// `eth_chainId`.
    pub async fn chain_id(&self) -> Result<u64, Error> {
        let value: U64 = self.call("eth_chainId", json!([])).await?;
        Ok(value.to())
    }

    /// `eth_getTransactionReceipt`; `None` when the node does not know the transaction (yet). A receipt for
    /// another hash or with a status other than 0 or 1 is a shape error, not an observation.
    pub async fn transaction_receipt(&self, hash: B256) -> Result<Option<TransactionReceipt>, Error> {
        let receipt: Option<TransactionReceipt> =
            self.call("eth_getTransactionReceipt", json!([hash])).await?;
        if let Some(receipt) = &receipt {
            if receipt.transaction_hash != hash {
                return Err(Error::Shape(format!(
                    "asked for {hash}, the node answered a receipt of {}",
                    receipt.transaction_hash
                )));
            }
            if receipt.status > U64::from(1) {
                return Err(Error::Shape(format!(
                    "status {} is neither 0 nor 1",
                    receipt.status
                )));
            }
        }
        Ok(receipt)
    }

    /// Polls for the receipt every two seconds until `timeout` has elapsed, requests included. Only a receipt
    /// that names a sealed block ends the wait early; a preconfirmed one is kept and reported as such at the
    /// deadline.
    pub async fn wait_for_receipt(&self, hash: B256, timeout: Duration) -> Result<Wait, Error> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut polls = 0u32;
        let mut preconfirmed = None;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, self.transaction_receipt(hash)).await {
                Err(_elapsed) => {
                    return Ok(preconfirmed.map_or(Wait::Unanswered { polls }, Wait::Preconfirmed));
                }
                Ok(Err(error)) => return Err(error),
                Ok(Ok(Some(receipt))) if receipt.is_sealed() => return Ok(Wait::Sealed(receipt)),
                Ok(Ok(Some(receipt))) => preconfirmed = Some(receipt),
                Ok(Ok(None)) => {}
            }
            polls += 1;
            let pause =
                Duration::from_secs(2).min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            tokio::time::sleep(pause).await;
        }
        Ok(match preconfirmed {
            Some(receipt) => Wait::Preconfirmed(receipt),
            None if polls > 0 => Wait::Unknown { polls },
            None => Wait::Unanswered { polls },
        })
    }

    async fn call<T: serde::de::DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, Error> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let answer: Value = self
            .http
            .post(self.url.clone())
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if answer.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || answer.get("id") != Some(&json!(1))
        {
            return Err(Error::Shape(format!(
                "not a JSON-RPC 2.0 answer to request 1: {}",
                answer.to_string().chars().take(200).collect::<String>()
            )));
        }
        if let Some(error) = answer.get("error") {
            return Err(Error::Rpc {
                code: error.get("code").and_then(Value::as_i64).unwrap_or_default(),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("no message")
                    .to_owned(),
            });
        }
        let result = answer
            .get("result")
            .ok_or_else(|| Error::Shape(format!("no result in {answer}")))?;
        serde_json::from_value(result.clone()).map_err(|e| Error::Shape(format!("{method}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn log_of<E: SolEvent>(address: Address, event: &E) -> Log {
        let data = event.encode_log_data();
        Log {
            address,
            topics: data.topics().to_vec(),
            data: data.data,
            log_index: None,
        }
    }

    fn receipt(logs: Vec<Log>) -> TransactionReceipt {
        TransactionReceipt {
            transaction_hash: B256::ZERO,
            status: U64::from(1),
            block_number: U64::from(7),
            block_hash: B256::ZERO,
            from: Address::ZERO,
            to: None,
            logs,
        }
    }

    #[test]
    fn transfers_of_the_asset_only() {
        let asset = address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e");
        let other = address!("0x0000000000000000000000000000000000000abc");
        let payer = address!("0x1111111111111111111111111111111111111111");
        let pay_to = address!("0x2222222222222222222222222222222222222222");
        let transfer = Transfer {
            from: payer,
            to: pay_to,
            value: U256::from(10_000),
        };
        let receipt = receipt(vec![
            log_of(other, &transfer),
            log_of(asset, &transfer),
            log_of(
                asset,
                &AuthorizationUsed {
                    authorizer: payer,
                    nonce: B256::repeat_byte(9),
                },
            ),
        ]);
        assert_eq!(
            receipt.transfers(asset),
            vec![Erc20Transfer {
                from: payer,
                to: pay_to,
                value: U256::from(10_000)
            }]
        );
        assert_eq!(
            receipt.authorizations_used(asset),
            vec![(payer, B256::repeat_byte(9))]
        );
        assert!(receipt.succeeded());
        assert!(!receipt.is_sealed());
    }

    #[test]
    fn a_receipt_deserialises_from_the_rpc_shape() {
        let json = json!({
            "transactionHash": "0xf850085300000000000000000000000000000000000000000000000000000001",
            "status": "0x1",
            "blockNumber": "0x1a2b3c",
            "blockHash": "0x00000000000000000000000000000000000000000000000000000000000000aa",
            "from": "0x0000000000000000000000000000000000000402",
            "to": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "logs": [{
                "address": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                           "0x0000000000000000000000001111111111111111111111111111111111111111",
                           "0x0000000000000000000000002222222222222222222222222222222222222222"],
                "data": "0x0000000000000000000000000000000000000000000000000000000000002710"
            }],
            "cumulativeGasUsed": "0x1234",
            "logsBloom": "0x00"
        });
        let receipt: TransactionReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(receipt.block_number, U64::from(0x001a_2b3c));
        let transfers = receipt.transfers(address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e"));
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].value, U256::from(10_000));
    }

    #[test]
    fn public_endpoints_are_known_for_the_paid_testnets() {
        for id in [84532, 11_155_111, 43113, 80002, 421_614, 11_155_420, 97, 59141] {
            assert!(public_rpc(id).is_some_and(|u| u.starts_with("https://")));
        }
        assert!(public_rpc(1).is_none());
    }
}
