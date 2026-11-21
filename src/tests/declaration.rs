//! Declarations (SPEC.md §20) against the merchant's app's vectors (vectors/app/app.json): the
//! keys of the channel and of a sale, the app's declaration opened as its sale, and a declaration
//! the crate makes for the same order opening with the vector's keys into exactly the app's JSON
//! (PORTING.md, "Definition of done", 2).

use super::support::vectors::{Field, assert_same, spec};
use crate::channel::{Channel, parse_channel};
use crate::declaration::{DeclarationInput, DeclaredPrice, declaration_event, open_declaration, registry_of};
use crate::derive::{
    Registry, channel_keys, outer_key, registry_address, sale_keys, sale_of, taker_key, taker_tag,
};
use crate::json::{self, Json};
use crate::lightning::bolt11;
use crate::nostr::event::{Event, valid_event};
use crate::nostr::nip44::{conversation_key, decrypt};
use crate::nostr::record::Opened;
use crate::runtime::OsRandom;
use crate::secret::Secret;
use crate::text::to_hex;

fn app() -> Json {
    spec("vectors/app/app.json")
}

fn integration_key(app: &Json) -> Secret {
    app.field("parsed").secret("integrationKey")
}

fn registry(app: &Json) -> Registry {
    let value = app.field("channel").field("value").field("v");
    registry_of(value.text("registryKey"), value.text("registryReader"))
}

/// An event of a vector, checked.
pub(crate) fn event_of(value: &Json) -> Event {
    valid_event(value).expect("a valid event")
}

/// The inside of a declaration, its text, opened with the outer key and the inner conversation
/// key; and the outside's plaintext.
fn open_with(event: &Event, outer: &Secret, inner: &Secret) -> (String, String) {
    let outside = decrypt(&event.content, outer).expect("the outside opens");
    let envelope = json::parse(&outside).expect("JSON");
    assert_eq!(envelope.get("t").and_then(Json::as_str), Some("registry-declaration"));
    let sealed = envelope.get("v").and_then(|v| v.get("sealed")).and_then(Json::as_str).expect("sealed");
    (decrypt(sealed, inner).expect("the inside opens"), outside)
}

#[test]
fn the_app_vectors_give_the_channel_keys_and_the_integration_mark_key() {
    let app = app();
    let key = integration_key(&app);
    let keys = channel_keys(&key);
    let derived = app.field("derived");
    assert_eq!(keys.address, derived.text("channelAddress"));
    assert_eq!(to_hex(keys.encryption_key.expose()), derived.text("channelEncryptionKey"));
    assert_eq!(to_hex(taker_key(&key).expose()), derived.text("takerKey"));
}

#[test]
fn the_app_vectors_hold_a_channel_the_key_alone_opens_as_the_crate_reads_it() {
    let app = app();
    let keys = channel_keys(&integration_key(&app));
    let channel = app.field("channel");
    let event = event_of(channel.field("event"));
    assert_eq!(event.pubkey, app.field("parsed").text("team"));
    assert_eq!(event.tags, vec![vec!["d".to_owned(), keys.address.clone()]]);
    let opened = json::parse(&decrypt(&event.content, &keys.encryption_key).unwrap()).unwrap();
    assert_same(&opened, channel.field("value"), "the channel");
    let value = channel.field("value").field("v");
    let Ok(Some(Channel::Active(active))) = parse_channel(value, event.created_at) else {
        panic!("an active channel")
    };
    assert_eq!(active.business_name, "Sunrise Bakery");
    assert_eq!(active.lightning_address, "sattleme02c6047f94@breez.tips");
    assert_eq!(active.registry_key, value.text("registryKey"));
    assert_eq!(active.registry_reader, value.text("registryReader"));
    assert_eq!(active.relays, Some(vec!["wss://relay.example".to_owned()]));
    // The app's channel of this vector names no web app: no checkout link.
    assert_eq!(active.checkout_origin, None);
    // Nor a tolerance of on-chain underpayments: none.
    assert_eq!(active.tolerance, 0);
    assert_eq!(active.updated_at, event.created_at);
}

#[test]
fn the_app_vectors_give_every_key_of_the_order_sale_and_of_its_declaration() {
    let app = app();
    let key = integration_key(&app);
    let registry = registry(&app);
    let declaration = app.field("declaration");
    let sale = sale_keys(&key, declaration.text("ref"));
    assert_eq!(to_hex(sale.key.expose()), declaration.text("saleKey"));
    assert_eq!(to_hex(sale.secret_key.expose()), declaration.text("saleSecret"));
    assert_eq!(sale.author, declaration.text("saleAuthor"));
    assert_eq!(taker_tag(&taker_key(&key), &sale.author), declaration.text("taker"));
    assert_eq!(registry_address(&registry.key, declaration.text("paymentHash")), declaration.text("address"));
    assert_eq!(
        to_hex(outer_key(&registry.key, declaration.text("address"), &sale.author).expose()),
        declaration.text("outerKey")
    );
    let inner = conversation_key(&sale.secret_key, &registry.reader).unwrap();
    assert_eq!(to_hex(inner.expose()), declaration.text("innerConversationKey"));
}

#[test]
fn the_app_vectors_hold_a_real_breez_tips_invoice_the_crate_decodes() {
    let app = app();
    let real = app.field("realInvoice");
    let decoded = bolt11::decode(real.text("invoice")).expect("a BOLT11 invoice");
    assert_eq!(decoded.network, "bc");
    assert_eq!(decoded.amount_msat, Some(real.digits("amountMsat")));
    assert_eq!(decoded.timestamp, real.int("timestamp"));
    assert_eq!(decoded.expiry_seconds, real.int("expirySeconds"));
    assert_eq!(decoded.payment_hash, real.text("paymentHash"));
    assert_eq!(decoded.description_hash.as_deref(), Some(real.text("descriptionHash")));
}

#[test]
fn the_app_vectors_hold_a_declaration_the_crate_opens_as_its_sale() {
    let app = app();
    let key = integration_key(&app);
    let registry = registry(&app);
    let declaration = app.field("declaration");
    let event = event_of(declaration.field("event"));
    let outside = decrypt(&event.content, &declaration.secret("outerKey")).unwrap();
    assert_eq!(outside.len() as i64, declaration.int("outsideBytes"));
    let Some(Opened::Valid { value: opened, event: opened_event }) =
        open_declaration(&event, &sale_of(&key, &registry, declaration.text("ref")))
    else {
        panic!("the sale opens it")
    };
    assert_eq!(opened_event, event);
    assert_eq!(opened.invoice, declaration.text("invoice"));
    assert_eq!(opened.decoded, bolt11::decode(declaration.text("invoice")).unwrap());
    assert_eq!(opened.verify_url, declaration.text("verifyUrl"));
    assert_same(&opened.price.to_json(), declaration.field("fiat"), "the price");
    assert_eq!(opened.note, declaration.text("note"));
    assert_eq!(opened.declared_at, event.created_at);
    assert_eq!(opened.rest, None);
    // Another order's sale does not open it.
    assert!(open_declaration(&event, &sale_of(&key, &registry, "ORD-1043")).is_none());
}

/// A declaration the crate makes for the order of the app's declaration.
fn made(app: &Json) -> Event {
    let key = integration_key(app);
    let registry = registry(app);
    let declaration = app.field("declaration");
    let sale = sale_of(&key, &registry, declaration.text("ref"));
    let fiat = declaration.field("fiat");
    let price = DeclaredPrice {
        minor: fiat.int("minor") as u64,
        digits: fiat.int("digits") as u32,
        currency: fiat.text("currency").to_owned(),
    };
    declaration_event(
        &DeclarationInput {
            sale: &sale,
            invoice: declaration.text("invoice"),
            verify_url: declaration.text("verifyUrl"),
            payment_hash: declaration.text("paymentHash"),
            price: &price,
            note: declaration.text("note"),
            created_at: declaration.field("event").int("created_at"),
            rest: None,
        },
        &OsRandom,
    )
    .expect("a declaration fits a record")
}

#[test]
fn a_declaration_the_crate_makes_opens_with_the_vector_keys_holding_what_the_app_holds() {
    let app = app();
    let declaration = app.field("declaration");
    let event = made(&app);
    assert!(valid_event(&event.to_json()).is_some());
    assert_eq!(event.kind, 30078.0);
    assert_eq!(event.pubkey, declaration.text("saleAuthor"));
    assert_eq!(event.created_at, declaration.field("event").int("created_at"));
    assert_eq!(event.tags, vec![vec!["d".to_owned(), declaration.text("address").to_owned()]]);
    let outer = declaration.secret("outerKey");
    let inner = declaration.secret("innerConversationKey");
    let (inside, outside) = open_with(&event, &outer, &inner);
    assert_eq!(outside.len() % 256, 0);
    let (app_inside, _) = open_with(&event_of(declaration.field("event")), &outer, &inner);
    // The same declaration, field for field and byte for byte, as the vector's (which the app made).
    assert_same(&json::parse(&inside).unwrap(), &json::parse(&app_inside).unwrap(), "the inside");
    assert_eq!(inside, app_inside);
    let expected = Json::object([
        ("version", Json::unsigned(1)),
        ("invoice", Json::from(declaration.text("invoice"))),
        ("verifyUrl", Json::from(declaration.text("verifyUrl"))),
        (
            "sale",
            Json::object([
                ("key", Json::from(declaration.text("saleKey"))),
                ("fiat", declaration.field("fiat").clone()),
                ("note", Json::from(declaration.text("note"))),
            ]),
        ),
        ("taker", Json::from(declaration.text("taker"))),
    ]);
    assert_same(&json::parse(&inside).unwrap(), &expected, "the inside");
}

#[test]
fn a_declaration_the_crate_makes_is_refused_with_another_registry_key_or_reader() {
    let app = app();
    let key = integration_key(&app);
    let registry = registry(&app);
    let reference = app.field("declaration").text("ref");
    let event = made(&app);
    let other_key = Registry { key: Secret::new([9; 32]), reader: registry.reader.clone() };
    assert!(open_declaration(&event, &sale_of(&key, &other_key, reference)).is_none());
    let other_reader = Registry {
        key: Secret::new(*registry.key.expose()),
        reader: app.field("parsed").text("team").to_owned(),
    };
    assert!(open_declaration(&event, &sale_of(&key, &other_reader, reference)).is_none());
    assert!(open_declaration(&event, &sale_of(&key, &registry, reference)).is_some());
}
