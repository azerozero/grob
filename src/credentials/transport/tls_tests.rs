use super::*;
use axum::{
    extract::{ConnectInfo, State},
    routing::get,
    Router,
};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

#[tokio::test]
async fn pinned_tls_verifies_names_negotiates_h2_and_reuses_connection() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["service.test".into()]).unwrap();
    let pem = cert.cert.pem();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        pem.as_bytes().to_vec(),
        cert.signing_key.serialize_pem().into_bytes(),
    )
    .await
    .unwrap();
    let peers = Arc::new(Mutex::new(HashSet::<SocketAddr>::new()));
    let app = Router::new()
        .route(
            "/",
            get(
                |State(peers): State<Arc<Mutex<HashSet<SocketAddr>>>>,
                 ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                    peers.lock().unwrap().insert(peer);
                    "ok"
                },
            ),
        )
        .with_state(peers.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    let url = endpoint(
        &format!("https://service.test:{}", address.port()),
        &[address.ip()],
    )
    .unwrap();
    let root = reqwest::Certificate::from_pem(pem.as_bytes()).unwrap();
    let client = client_builder(&url, &[address.ip()])
        .unwrap()
        .add_root_certificate(root.clone())
        .build()
        .unwrap();
    for _ in 0..16 {
        let response = client.get(url.clone()).send().await.unwrap();
        assert_eq!(response.version(), reqwest::Version::HTTP_2);
        assert_eq!(response.text().await.unwrap(), "ok");
    }
    assert_eq!(peers.lock().unwrap().len(), 1);
    let mut wrong = url.clone();
    wrong.set_host(Some("wrong.test")).unwrap();
    assert!(client_builder(&wrong, &[address.ip()])
        .unwrap()
        .add_root_certificate(root)
        .build()
        .unwrap()
        .get(wrong)
        .send()
        .await
        .is_err());
    assert!(super::client(&url, &[address.ip()])
        .unwrap()
        .get(url)
        .send()
        .await
        .is_err());
    server.abort();
}
