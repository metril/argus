//! Integration tests for WebSocket proxying

#![cfg(feature = "websockets")]

use proxy_core::websocket::{extract_ws_target, is_websocket_upgrade};

#[test]
fn test_websocket_upgrade_detection() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
    headers.insert(hyper::header::CONNECTION, "Upgrade".parse().unwrap());

    assert!(is_websocket_upgrade(&headers));
}

#[test]
fn test_websocket_upgrade_detection_case_insensitive() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(hyper::header::UPGRADE, "WebSocket".parse().unwrap());
    headers.insert(hyper::header::CONNECTION, "upgrade".parse().unwrap());

    assert!(is_websocket_upgrade(&headers));
}

#[test]
fn test_not_websocket_upgrade() {
    let headers = hyper::HeaderMap::new();
    assert!(!is_websocket_upgrade(&headers));
}

#[test]
fn test_extract_ws_target_with_full_uri() {
    let uri = "https://example.com:443/ws/chat".parse::<hyper::Uri>().unwrap();
    let headers = hyper::HeaderMap::new();

    let target = extract_ws_target(&uri, &headers).unwrap();
    // Note: port is not included in output since uri.host() doesn't include it
    assert_eq!(target, "wss://example.com/ws/chat");
}

#[test]
fn test_extract_ws_target_with_path_only() {
    let uri = "/ws/chat".parse::<hyper::Uri>().unwrap();
    let mut headers = hyper::HeaderMap::new();
    headers.insert(hyper::header::HOST, "example.com".parse().unwrap());

    let target = extract_ws_target(&uri, &headers).unwrap();
    assert_eq!(target, "wss://example.com/ws/chat");
}

#[test]
fn test_extract_ws_target_http_port() {
    let uri = "http://example.com:80/ws".parse::<hyper::Uri>().unwrap();
    let headers = hyper::HeaderMap::new();

    let target = extract_ws_target(&uri, &headers).unwrap();
    // Note: port is not included in output since uri.host() doesn't include it
    assert_eq!(target, "ws://example.com/ws");
}

#[test]
fn test_extract_ws_target_missing_host() {
    let uri = "/ws/chat".parse::<hyper::Uri>().unwrap();
    let headers = hyper::HeaderMap::new();

    let result = extract_ws_target(&uri, &headers);
    assert!(result.is_err());
}
