//! Tests for HTTP/2 support

use proxy_core::http2;

#[test]
fn test_http2_protocol_detection() {
    assert!(http2::is_http2_protocol(b"h2"));
    assert!(!http2::is_http2_protocol(b"http/1.1"));
    assert!(!http2::is_http2_protocol(b"h3"));
    assert!(!http2::is_http2_protocol(b""));
}
