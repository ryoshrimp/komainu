use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::routing::get;
use komainu_adapter_http::{JwksFetcherConfig, ReqwestJwksFetcher};
use komainu_application::{JwksFetchError, JwksFetcher};
use komainu_domain::JwksUri;

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn uri(addr: SocketAddr, path: &str) -> JwksUri {
    JwksUri::new_unchecked_for_testing(format!("http://{addr}{path}"))
}

fn fetcher(timeout: Duration) -> ReqwestJwksFetcher {
    ReqwestJwksFetcher::new(JwksFetcherConfig {
        timeout,
        allow_non_global_for_testing: true,
        ..JwksFetcherConfig::default()
    })
    .unwrap()
}

#[tokio::test]
async fn returns_body_on_200() {
    let addr = serve(Router::new().route("/jwks", get(|| async { r#"{"keys":[]}"# }))).await;
    let body = fetcher(Duration::from_secs(5))
        .fetch(&uri(addr, "/jwks"))
        .await
        .unwrap();
    assert_eq!(body, r#"{"keys":[]}"#);
}

#[tokio::test]
async fn does_not_follow_redirects() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let app = Router::new()
        .route(
            "/redirect",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/target")]) }),
        )
        .route(
            "/target",
            get(move || {
                let h = h.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    "{}"
                }
            }),
        );
    let addr = serve(app).await;
    let err = fetcher(Duration::from_secs(5))
        .fetch(&uri(addr, "/redirect"))
        .await
        .unwrap_err();
    assert!(matches!(err, JwksFetchError::Status(302)), "{err:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_200_is_status_error() {
    let app = Router::new().route("/e", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }));
    let addr = serve(app).await;
    let err = fetcher(Duration::from_secs(5))
        .fetch(&uri(addr, "/e"))
        .await
        .unwrap_err();
    assert!(matches!(err, JwksFetchError::Status(500)), "{err:?}");
}

#[tokio::test]
async fn slow_response_times_out() {
    let app = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(6)).await;
            "{}"
        }),
    );
    let addr = serve(app).await;
    let err = fetcher(Duration::from_secs(1))
        .fetch(&uri(addr, "/slow"))
        .await
        .unwrap_err();
    assert!(matches!(err, JwksFetchError::Timeout), "{err:?}");
}

fn sized_app() -> Router {
    let body = |n: usize| async move { "a".repeat(n) };
    Router::new()
        .route("/len/ok", get(move || body(65536)))
        .route("/len/big", get(move || body(65537)))
}

/// Serves `n` bytes with `Transfer-Encoding: chunked` (no Content-Length) to every connection.
async fn serve_chunked(n: usize) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let mut out =
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        .to_vec();
                out.extend_from_slice(format!("{n:x}\r\n").as_bytes());
                out.extend(std::iter::repeat_n(b'a', n));
                out.extend_from_slice(b"\r\n0\r\n\r\n");
                let _ = sock.write_all(&out).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn body_size_limit() {
    let addr = serve(sized_app()).await;
    let f = fetcher(Duration::from_secs(5));
    assert_eq!(f.fetch(&uri(addr, "/len/ok")).await.unwrap().len(), 65536);
    let err = f.fetch(&uri(addr, "/len/big")).await.unwrap_err();
    assert!(matches!(err, JwksFetchError::TooLarge), "{err:?}");

    let ok = serve_chunked(65536).await;
    assert_eq!(f.fetch(&uri(ok, "/")).await.unwrap().len(), 65536);
    let big = serve_chunked(65537).await;
    let err = f.fetch(&uri(big, "/")).await.unwrap_err();
    assert!(matches!(err, JwksFetchError::TooLarge), "{err:?}");
}

#[tokio::test]
async fn default_config_forbids_non_global_destinations() {
    let f = ReqwestJwksFetcher::new(JwksFetcherConfig::default()).unwrap();
    for u in [
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://10.0.0.1/",
        "https://169.254.169.254/",
        "https://localhost/",
    ] {
        let err = f
            .fetch(&JwksUri::new_unchecked_for_testing(u.to_owned()))
            .await
            .unwrap_err();
        assert!(matches!(err, JwksFetchError::Forbidden), "{u}: {err:?}");
    }
}
