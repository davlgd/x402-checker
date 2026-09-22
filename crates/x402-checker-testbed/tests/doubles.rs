//! The doubles answer as scripted and record what they receive.

use std::time::Duration;

use serde_json::{Value, json};
use x402_checker_testbed::{
    Endpoint, Facilitator, FacilitatorConfig, Recorder, Script, SettleOutcome, VerifyOutcome, Witness,
    WitnessScript,
};

fn request_body(nonce: &str) -> Value {
    json!({
        "x402Version": 2,
        "paymentPayload": {
            "x402Version": 2,
            "accepted": offer(),
            "payload": { "signature": "0x00", "authorization": { "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66", "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "value": "10000", "validAfter": "0", "validBefore": "1", "nonce": nonce } }
        },
        "paymentRequirements": offer(),
    })
}

fn offer() -> Value {
    json!({ "scheme": "exact", "network": "eip155:84532", "amount": "10000", "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "maxTimeoutSeconds": 60, "extra": { "name": "USDC", "version": "2" } })
}

#[tokio::test]
async fn facilitator_answers_from_its_script_and_records_calls() {
    let recorder = Recorder::new();
    let config = FacilitatorConfig::exact_evm("eip155:84532", "0x1234567890abcdef1234567890abcdef12345678");
    let facilitator = Facilitator::spawn(
        "127.0.0.1:0".parse().unwrap(),
        config,
        Script::default(),
        recorder.clone(),
    )
    .await
    .unwrap();
    let http = reqwest::Client::new();

    let supported: Value = http
        .get(format!("{}/supported", facilitator.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(supported["kinds"][0]["network"], "eip155:84532");
    assert_eq!(
        supported["signers"]["eip155:*"][0],
        "0x1234567890abcdef1234567890abcdef12345678"
    );

    let verify: Value = http
        .post(format!("{}/verify", facilitator.url()))
        .json(&request_body("0x01"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verify["isValid"], true);
    assert_eq!(verify["payer"], "0x857b06519E91e3A54538791bDbb0E22373e36b66");

    let settle: Value = http
        .post(format!("{}/settle", facilitator.url()))
        .json(&request_body("0x01"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settle["success"], true);
    assert_eq!(settle["network"], "eip155:84532");

    // the same nonce again: the network's replay primitive is consumed
    let again: Value = http
        .post(format!("{}/settle", facilitator.url()))
        .json(&request_body("0x01"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(again["success"], false);
    assert_eq!(again["errorReason"], "invalid_transaction_state");

    let calls = recorder.calls();
    let endpoints: Vec<_> = calls.iter().map(|c| c.endpoint).collect();
    assert_eq!(
        endpoints,
        [
            Endpoint::Supported,
            Endpoint::Verify,
            Endpoint::Settle,
            Endpoint::Settle
        ]
    );
    assert_eq!(
        calls[1].body_json.as_ref().unwrap()["paymentRequirements"]["amount"],
        "10000"
    );
    assert!(
        calls
            .iter()
            .all(|c| c.finished_at.is_some() && c.answered_status == Some(200))
    );
    assert_eq!(calls[1].headers["content-type"], "application/json");
}

#[tokio::test]
async fn facilitator_scripts_pending_rejection_raw_and_sidechannel() {
    let recorder = Recorder::new();
    let config = FacilitatorConfig::exact_evm("eip155:84532", "0x1234567890abcdef1234567890abcdef12345678");
    let facilitator = Facilitator::spawn(
        "127.0.0.1:0".parse().unwrap(),
        config,
        Script::default(),
        recorder,
    )
    .await
    .unwrap();
    let http = reqwest::Client::new();
    let settle_url = format!("{}/settle", facilitator.url());

    facilitator.set_script(Script {
        settle: SettleOutcome::Pending {
            transaction: "0xdead".into(),
        },
        extension_responses: Some(json!({ "bazaar": { "recorded": true } })),
        ..Script::default()
    });
    let response = http
        .post(&settle_url)
        .json(&request_body("0x02"))
        .send()
        .await
        .unwrap();
    assert!(response.headers().contains_key("extension-responses"));
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["errorReason"], "settlement_pending");
    assert_eq!(body["transaction"], "0xdead");

    facilitator.set_script(Script {
        verify: VerifyOutcome::Invalid {
            reason: "insufficient_funds".into(),
        },
        settle: SettleOutcome::Rejected {
            reason: "invalid_exact_evm_payload_signature".into(),
            transaction: String::new(),
        },
        ..Script::default()
    });
    let verify: Value = http
        .post(format!("{}/verify", facilitator.url()))
        .json(&request_body("0x03"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verify["isValid"], false);
    assert_eq!(verify["invalidReason"], "insufficient_funds");
    let settle: Value = http
        .post(&settle_url)
        .json(&request_body("0x03"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settle["success"], false);
    assert_eq!(settle["transaction"], "");

    facilitator.set_script(Script {
        settle: SettleOutcome::Raw {
            status: 502,
            content_type: "text/html".into(),
            body: "<h1>Bad gateway</h1>".into(),
        },
        ..Script::default()
    });
    let raw = http
        .post(&settle_url)
        .json(&request_body("0x04"))
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 502);
    assert_eq!(raw.headers()["content-type"], "text/html");

    facilitator.set_script(Script {
        settle: SettleOutcome::Hang {
            after: Duration::from_millis(300),
            then: Box::new(SettleOutcome::Settled {
                transaction: "0x01".into(),
            }),
        },
        ..Script::default()
    });
    let started = std::time::Instant::now();
    let late: Value = http
        .post(&settle_url)
        .json(&request_body("0x05"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(late["success"], true);
}

#[tokio::test]
async fn witness_records_and_answers_as_scripted() {
    let recorder = Recorder::new();
    let witness = Witness::spawn(
        "127.0.0.1:0".parse().unwrap(),
        WitnessScript::default(),
        recorder.clone(),
    )
    .await
    .unwrap();
    let http = reqwest::Client::new();

    let ok = http
        .get(format!("{}/some/path?x=1", witness.url()))
        .header("X-Test", "yes")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let body: Value = ok.json().await.unwrap();
    assert_eq!(body["witness"], true);
    assert_eq!(body["path"], "/some/path?x=1");

    witness.set_script(WitnessScript {
        status: 503,
        latency: Duration::ZERO,
    });
    let failing = http.post(witness.url()).body("payload").send().await.unwrap();
    assert_eq!(failing.status(), 503);

    let calls = recorder.calls_to(Endpoint::Backend);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].headers["x-test"], "yes");
    assert_eq!(calls[1].method, "POST");
    assert_eq!(calls[1].body_text, "payload");
    assert_eq!(calls[1].answered_status, Some(503));
}
