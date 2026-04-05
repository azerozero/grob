use cucumber::{given, then};

use crate::world::E2eWorld;

#[given("the e2e pod is running")]
async fn pod_is_running(world: &mut E2eWorld) {
    world.init();
    // Pod lifecycle is managed externally (Makefile / CI).
    // Here we just verify connectivity.
}

#[given(regex = r"grob is healthy on port (\d+)")]
async fn grob_healthy(world: &mut E2eWorld, port: u16) {
    let url = format!("http://127.0.0.1:{port}/health");
    let resp = reqwest::get(&url).await.expect("grob /health unreachable");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "grob not healthy on port {port}"
    );
    world.grob_host = format!("127.0.0.1:{port}");
}

#[given(regex = r"VidaiMock is healthy on port (\d+)")]
async fn vidaimock_healthy(_world: &mut E2eWorld, port: u16) {
    let url = format!("http://127.0.0.1:{port}/health");
    let resp = reqwest::get(&url).await.expect("VidaiMock unreachable");
    assert!(
        resp.status().is_success(),
        "VidaiMock not healthy on port {port}"
    );
}

#[given(regex = r"Toxiproxy API is available on port (\d+)")]
async fn toxiproxy_available(world: &mut E2eWorld, port: u16) {
    let url = format!("http://127.0.0.1:{port}/version");
    let resp = reqwest::get(&url).await.expect("Toxiproxy unreachable");
    assert!(
        resp.status().is_success(),
        "Toxiproxy not healthy on port {port}"
    );
    world.toxi_host = format!("127.0.0.1:{port}");
}

#[then(regex = r#"the response header "(.+)" exists"#)]
async fn header_exists(world: &mut E2eWorld, header: String) {
    assert!(
        world.last_http_headers.contains_key(&header.to_lowercase()),
        "header '{header}' not found in response"
    );
}

#[then(regex = r#"the response header "(.+)" does not contain "(.+)""#)]
async fn header_not_contains(world: &mut E2eWorld, header: String, value: String) {
    let hdr = world
        .last_http_headers
        .get(&header.to_lowercase())
        .cloned()
        .unwrap_or_default();
    assert!(
        !hdr.contains(&value),
        "header '{header}' contains '{value}': {hdr}"
    );
}
