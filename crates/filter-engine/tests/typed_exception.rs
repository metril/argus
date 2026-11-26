//! A type-restricted exception must not allow requests of other types.

use filter_engine::{build_set, ListFormat, ListInput, SharedEngine};

fn engine(rules: &str) -> SharedEngine {
    let e = SharedEngine::new();
    build_set(&[ListInput {
        id: "l".into(),
        content: format!("{rules}\n"),
        format: ListFormat::Abp,
        allowlist: false,
        trusted: false,
        includes: Default::default(),
    }])
    .install_into(&e);
    e
}

#[test]
fn image_only_exception_does_not_allow_a_subframe() {
    let e = engine("||amazon-adsystem.com^\n@@||amazon-adsystem.com/widgets/q?$image,third-party");
    let u = "https://ws-na.amazon-adsystem.com/widgets/q?ServiceVersion=1";
    let page = "https://canyoublockit.com/x/";
    assert!(e.check(u, page, "sub_frame").blocked, "sub_frame");
    assert!(e.check(u, page, "script").blocked, "script");
    assert!(!e.check(u, page, "image").blocked, "image allowed");
}
