//! `get_status` and `wait_for_payment` of a Lightning invoice (SPEC.md §22, §23): LUD-21's verify
//! answers, checked; the invoice's end and its grace; a stored invoice checked; failures retried.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::support::http::{Answer, Call};
use super::support::j;
use super::support::merchant::{TestMerchant, Warnings};
use crate::client::{Client, WaitOptions};
use crate::error::ErrorCode;
use crate::json::Json;
use crate::model::{Invoice, InvoiceToCheck, PaymentStatus};
use crate::order::Order;

async fn setup() -> (TestMerchant, Client, Invoice) {
    let merchant = TestMerchant::new().start();
    merchant.publish_channel(&merchant.channel_value(100, j!({})), 100);
    let client = merchant.client().build().unwrap();
    let invoice = client.create_invoice(&Order::sats("P-1", 2100).duration_seconds(600)).await.unwrap();
    (merchant, client, invoice)
}

/// breez.tips's verify answer for the invoice, replaced.
fn verify_answers(merchant: &TestMerchant, json: Json, status: u16) {
    merchant.set_override(Some(move |call: &Call| {
        call.path().contains("/verify/").then(|| Answer::status_json(status, &json))
    }));
}

fn json(status: &PaymentStatus) -> serde_json::Value {
    serde_json::to_value(status).unwrap()
}

mod get_status {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn is_open_then_paid_with_the_preimage_the_proof_of_payment() {
        let (merchant, client, invoice) = setup().await;
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "open", "expiresAt": invoice.expires_at, "received": "0", "rest": null })
        );
        let hash = invoice.payment_hash.clone().unwrap();
        merchant.pay_invoice(&hash);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "lightning", "preimage": merchant.invoice(&hash).unwrap().preimage })
        );
        // A look, without state: from the stored invoice, as JSON.
        let stored = InvoiceToCheck::from_json(&invoice.to_json()).unwrap();
        assert_eq!(client.get_status(stored).await.unwrap().state(), "paid");
    }

    #[tokio::test(start_paused = true)]
    async fn reads_the_invoice_whatever_its_case_and_an_upper_case_preimage() {
        let (merchant, client, invoice) = setup().await;
        let made = merchant.invoice(invoice.payment_hash.as_deref().unwrap()).unwrap();
        verify_answers(
            &merchant,
            j!({ "status": "OK", "settled": true, "preimage": made.preimage.to_uppercase(), "pr": made.pr.to_uppercase() }),
            200,
        );
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "paid", "method": "lightning", "preimage": made.preimage })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_an_answer_about_another_invoice_and_a_wrong_preimage() {
        let (merchant, client, invoice) = setup().await;
        let made = merchant.invoice(invoice.payment_hash.as_deref().unwrap()).unwrap();
        let other = client.create_invoice(&Order::sats("P-2", 2100).duration_seconds(600)).await.unwrap();
        for answer in [
            j!({ "status": "OK", "settled": true, "preimage": made.preimage, "pr": other.bolt11 }),
            j!({ "status": "OK", "settled": true, "preimage": "11".repeat(32), "pr": made.pr }),
            j!({ "status": "OK", "settled": true, "preimage": null, "pr": made.pr }),
            j!({ "status": "OK", "settled": true, "preimage": made.preimage }),
        ] {
            verify_answers(&merchant, answer.clone(), 200);
            let error = client.get_status(&invoice).await.unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInvoice, "{}", crate::json::stringify(&answer));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn is_expired_120_s_after_the_invoice_end_not_before() {
        let (merchant, client, invoice) = setup().await;
        merchant.set_now(invoice.expires_at + 119);
        assert_eq!(client.get_status(&invoice).await.unwrap().state(), "open");
        merchant.set_now(invoice.expires_at + 120);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "0" })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn is_expired_on_not_found_after_the_grace_only() {
        let (merchant, client, invoice) = setup().await;
        verify_answers(&merchant, j!({ "status": "ERROR", "reason": "Not found" }), 200);
        merchant.set_now(invoice.expires_at + 119);
        assert_eq!(client.get_status(&invoice).await.unwrap().state(), "open");
        merchant.set_now(invoice.expires_at + 120);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "0" })
        );
        verify_answers(&merchant, j!({ "status": "ERROR", "reason": "Not found" }), 404);
        assert_eq!(
            json(&client.get_status(&invoice).await.unwrap()),
            serde_json::json!({ "state": "expired", "received": "0" })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_the_invoice_open_on_any_other_error_before_the_grace_retries_after() {
        let (merchant, client, invoice) = setup().await;
        verify_answers(&merchant, j!({ "status": "ERROR", "reason": "Internal server error" }), 200);
        assert_eq!(client.get_status(&invoice).await.unwrap().state(), "open");
        merchant.set_now(invoice.expires_at + 600);
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
    }

    #[tokio::test(start_paused = true)]
    async fn fails_network_retryable_when_breez_tips_does_not_answer() {
        let (merchant, client, invoice) = setup().await;
        for status in [500, 502, 429] {
            verify_answers(&merchant, j!({ "status": "ERROR", "reason": "Not found" }), status);
            let error = client.get_status(&invoice).await.unwrap_err();
            assert_eq!(error.code(), ErrorCode::Network, "{status}");
            assert!(error.retryable());
        }
        // No answer at all: a failed connection.
        let unreachable = merchant
            .client()
            .http_client(super::super::support::http::FakeHttp::new(|_| None))
            .build()
            .unwrap();
        assert_eq!(unreachable.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
        merchant.set_override(Some(|call: &Call| {
            call.path().contains("/verify/").then(|| Answer::text(200, "<html>"))
        }));
        assert_eq!(client.get_status(&invoice).await.unwrap_err().code(), ErrorCode::Network);
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_a_stored_invoice_that_is_not_what_create_invoice_gave() {
        let (_merchant, client, invoice) = setup().await;
        let changes: [fn(&mut Invoice); 4] = [
            |invoice| invoice.payment_hash = Some("00".repeat(32)),
            |invoice| invoice.expires_at += 3600,
            |invoice| invoice.verify_url = Some("http://breez.tips/x".to_owned()),
            |invoice| invoice.bolt11 = Some("lnbc1".to_owned()),
        ];
        for change in changes {
            let mut changed = invoice.clone();
            change(&mut changed);
            let error = client.get_status(&changed).await.unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidOrder, "{changed:?}");
        }
    }
}

mod wait_for_payment {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn checks_until_the_invoice_is_paid_network_errors_retried() {
        let (merchant, client, invoice) = setup().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let hash = invoice.payment_hash.clone().unwrap();
        let marker = merchant.pay_marker();
        {
            let calls = calls.clone();
            merchant.set_override(Some(move |call: &Call| {
                if !call.path().contains("/verify/") {
                    return None;
                }
                let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if count == 2 {
                    // No answer: the check fails, and is made again.
                    return Some(Answer::text(503, "down"));
                }
                if count == 3 {
                    marker(&hash);
                }
                None
            }));
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let options = WaitOptions::default()
            .interval_ms(250)
            .on_status(move |status| recorded.lock().unwrap().push(status.state()));
        let last = client.wait_for_payment(&invoice, options).await.unwrap();
        assert_eq!(last.state(), "paid");
        assert_eq!(*seen.lock().unwrap(), vec!["open", "paid"]);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn logs_a_failure_each_check_meets_again_once_and_again_only_after_it_stopped() {
        let (merchant, _, invoice) = setup().await;
        let warnings = Warnings::default();
        let logged = merchant.client().logger(warnings.clone()).build().unwrap();
        // Down for 3 checks, up for 1, down for 2 again, then paid.
        let down = [true, true, true, false, true, true];
        let calls = Arc::new(AtomicUsize::new(0));
        let hash = invoice.payment_hash.clone().unwrap();
        let marker = merchant.pay_marker();
        {
            let calls = calls.clone();
            merchant.set_override(Some(move |call: &Call| {
                if !call.path().contains("/verify/") {
                    return None;
                }
                let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if count > down.len() {
                    marker(&hash);
                }
                down.get(count - 1).copied().unwrap_or(false).then(|| Answer::text(503, "down"))
            }));
        }
        assert_eq!(
            logged.wait_for_payment(&invoice, WaitOptions::default().interval_ms(250)).await.unwrap().state(),
            "paid"
        );
        assert_eq!(calls.load(Ordering::SeqCst), down.len() + 1);
        let warning = "sattleme-checkout: the payment check failed (breez.tips answered HTTP 503 without an LNURL answer); checked again";
        assert_eq!(warnings.all(), vec![warning.to_owned(), warning.to_owned()]);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_at_expired() {
        let (merchant, client, invoice) = setup().await;
        merchant.set_now(invoice.expires_at + 120);
        let last = client.wait_for_payment(&invoice, WaitOptions::default().interval_ms(250)).await.unwrap();
        assert_eq!(json(&last), serde_json::json!({ "state": "expired", "received": "0" }));
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_its_future_is_dropped() {
        let (_merchant, client, invoice) = setup().await;
        let wait = client.wait_for_payment(&invoice, WaitOptions::default().interval_ms(250));
        // The order cancelled: the shop drops the wait.
        assert!(tokio::time::timeout(Duration::from_millis(300), wait).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn stops_on_an_answer_that_is_not_about_this_invoice() {
        let (merchant, client, invoice) = setup().await;
        verify_answers(&merchant, j!({ "status": "OK", "settled": false, "pr": "lnbc1other" }), 200);
        let error =
            client.wait_for_payment(&invoice, WaitOptions::default().interval_ms(250)).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInvoice);
    }
}

/// Every call's future can be spawned (`Send + 'static` once it owns what it borrows): the
/// integrator's server runs calls on any task.
#[test]
fn every_call_can_be_spawned() {
    fn spawnable<F: Future + Send + 'static>(_: F) {}
    let merchant = TestMerchant::new();
    let client = merchant.client().build().unwrap();
    let invoice = InvoiceToCheck {
        reference: Some("S-1".to_owned()),
        bolt11: None,
        payment_hash: None,
        verify_url: None,
        onchain_address: None,
        sats: 1000,
        expires_at: 1_791_379_180,
    };
    let order = Order::sats("S-1", 1000);
    spawnable({
        let client = client.clone();
        async move { client.merchant().await }
    });
    spawnable({
        let (client, order) = (client.clone(), order.clone());
        async move { client.create_invoice(&order).await }
    });
    spawnable({
        let (client, invoice) = (client.clone(), invoice.clone());
        async move { client.get_status(&invoice).await }
    });
    spawnable({
        let (client, invoice) = (client.clone(), invoice.clone());
        async move { client.wait_for_payment(&invoice, WaitOptions::default()).await }
    });
    spawnable(async move { client.find_invoices("S-1").await });
}
