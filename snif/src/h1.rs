//! HTTP/1.x parsing utilities

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

// Re-export HTTP types from h2session for use across all HTTP versions
pub use h2session::{HttpRequest, HttpResponse};

/// Check if data starts with an HTTP/1.x request
pub fn is_http1_request(data: &[u8]) -> bool {
    data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
        || data.starts_with(b"PATCH ")
        || data.starts_with(b"CONNECT ")
}

/// Check if data starts with an HTTP/1.x response
pub fn is_http1_response(data: &[u8]) -> bool {
    data.starts_with(b"HTTP/1.0") || data.starts_with(b"HTTP/1.1")
}

/// Try to parse an HTTP/1.x request, returning Some only if complete.
/// This combines header parsing and body completeness checking in one pass.
pub fn try_parse_http1_request(data: &[u8], timestamp_ns: u64) -> Option<HttpRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let body_offset = match req.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        _ => return None, // Headers incomplete
    };

    // Check body completeness using parsed headers
    let body_data = &data[body_offset..];
    if !is_body_complete(req.headers, body_data, data) {
        return None;
    }

    let method = Method::from_bytes(req.method?.as_bytes()).ok()?;
    let uri: Uri = req.path?.parse().ok()?;

    let mut header_map = HeaderMap::new();
    for h in req.headers.iter() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(h.name.as_bytes()),
            HeaderValue::from_bytes(h.value),
        ) {
            header_map.insert(name, value);
        }
    }

    Some(HttpRequest {
        method,
        uri,
        headers: header_map,
        body: body_data.to_vec(),
        timestamp_ns,
    })
}

/// Try to parse an HTTP/1.x response, returning Some only if complete.
/// This combines header parsing and body completeness checking in one pass.
pub fn try_parse_http1_response(data: &[u8], timestamp_ns: u64) -> Option<HttpResponse> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);

    let body_offset = match res.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        _ => return None, // Headers incomplete
    };

    // Check body completeness using parsed headers
    let body_data = &data[body_offset..];
    if !is_body_complete(res.headers, body_data, data) {
        return None;
    }

    let status = StatusCode::from_u16(res.code?).ok()?;

    let mut header_map = HeaderMap::new();
    for h in res.headers.iter() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(h.name.as_bytes()),
            HeaderValue::from_bytes(h.value),
        ) {
            header_map.insert(name, value);
        }
    }

    Some(HttpResponse {
        status,
        headers: header_map,
        body: body_data.to_vec(),
        timestamp_ns,
    })
}

/// Check if the body is complete based on parsed headers.
/// Handles Content-Length, Transfer-Encoding: chunked, and no-body cases.
fn is_body_complete(headers: &[httparse::Header<'_>], body: &[u8], full_data: &[u8]) -> bool {
    // Look for Content-Length (case-insensitive via httparse)
    for h in headers.iter() {
        if h.name.eq_ignore_ascii_case("Content-Length")
            && let Ok(len_str) = std::str::from_utf8(h.value)
        {
            if let Ok(content_length) = len_str.trim().parse::<usize>() {
                return body.len() >= content_length;
            }
            return false; // Invalid Content-Length
        }
    }

    // Check for Transfer-Encoding: chunked
    for h in headers.iter() {
        if h.name.eq_ignore_ascii_case("Transfer-Encoding")
            && let Ok(value) = std::str::from_utf8(h.value)
            && value.to_ascii_lowercase().contains("chunked")
        {
            // Look for final chunk (0\r\n\r\n)
            return full_data.windows(5).any(|w| w == b"0\r\n\r\n");
        }
    }

    // No Content-Length and not chunked - complete after headers (e.g., GET request)
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http1_request() {
        assert!(is_http1_request(b"GET / HTTP/1.1\r\n"));
        assert!(is_http1_request(b"POST /api HTTP/1.1\r\n"));
        assert!(is_http1_request(b"PUT /resource HTTP/1.1\r\n"));
        assert!(is_http1_request(b"DELETE /item HTTP/1.1\r\n"));
        assert!(is_http1_request(b"HEAD / HTTP/1.1\r\n"));
        assert!(is_http1_request(b"OPTIONS * HTTP/1.1\r\n"));
        assert!(is_http1_request(b"PATCH /update HTTP/1.1\r\n"));
        assert!(is_http1_request(b"CONNECT host:443 HTTP/1.1\r\n"));

        assert!(!is_http1_request(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_http1_request(b"PRI * HTTP/2.0\r\n"));
    }

    #[test]
    fn test_is_http1_response() {
        assert!(is_http1_response(b"HTTP/1.1 200 OK\r\n"));
        assert!(is_http1_response(b"HTTP/1.0 404 Not Found\r\n"));

        assert!(!is_http1_response(b"GET / HTTP/1.1\r\n"));
        assert!(!is_http1_response(b"HTTP/2 200 OK\r\n"));
    }

    // =========================================================================
    // try_parse_http1_request tests
    // =========================================================================

    #[test]
    fn test_try_parse_request_incomplete_headers() {
        // Headers not complete (no \r\n\r\n)
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(
            try_parse_http1_request(data, 0).is_none(),
            "Should return None for incomplete headers"
        );
    }

    #[test]
    fn test_try_parse_request_complete_no_body() {
        // GET request with no body - complete after headers
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = try_parse_http1_request(data, 12345);
        assert!(result.is_some(), "Should parse complete GET request");
        let req = result.unwrap();
        assert_eq!(req.method, Method::GET);
        assert_eq!(req.timestamp_ns, 12345);
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_try_parse_request_content_length_complete() {
        let data = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some(), "Should parse complete POST with body");
        let req = result.unwrap();
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn test_try_parse_request_content_length_incomplete() {
        // Content-Length says 10 but only 5 bytes provided
        let data = b"POST /api HTTP/1.1\r\nContent-Length: 10\r\n\r\nhello";
        assert!(
            try_parse_http1_request(data, 0).is_none(),
            "Should return None when body is incomplete"
        );
    }

    #[test]
    fn test_try_parse_request_content_length_case_insensitive() {
        // Mixed case Content-Length header
        let data = b"POST /api HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello";
        let result = try_parse_http1_request(data, 0);
        assert!(
            result.is_some(),
            "Should handle case-insensitive Content-Length"
        );
        assert_eq!(result.unwrap().body, b"hello");
    }

    #[test]
    fn test_try_parse_request_chunked_complete() {
        let data =
            b"POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let result = try_parse_http1_request(data, 0);
        assert!(result.is_some(), "Should parse complete chunked request");
    }

    #[test]
    fn test_try_parse_request_chunked_incomplete() {
        // Chunked but missing final 0\r\n\r\n
        let data = b"POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(
            try_parse_http1_request(data, 0).is_none(),
            "Should return None for incomplete chunked"
        );
    }

    // =========================================================================
    // try_parse_http1_response tests
    // =========================================================================

    #[test]
    fn test_try_parse_response_incomplete_headers() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
        assert!(
            try_parse_http1_response(data, 0).is_none(),
            "Should return None for incomplete response headers"
        );
    }

    #[test]
    fn test_try_parse_response_complete_no_body() {
        let data = b"HTTP/1.1 204 No Content\r\n\r\n";
        let result = try_parse_http1_response(data, 67890);
        assert!(result.is_some(), "Should parse complete 204 response");
        let resp = result.unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        assert_eq!(resp.timestamp_ns, 67890);
    }

    #[test]
    fn test_try_parse_response_content_length_complete() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nHello World";
        let result = try_parse_http1_response(data, 0);
        assert!(result.is_some(), "Should parse complete response with body");
        let resp = result.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"Hello World");
    }

    #[test]
    fn test_try_parse_response_content_length_incomplete() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nHello";
        assert!(
            try_parse_http1_response(data, 0).is_none(),
            "Should return None when response body is incomplete"
        );
    }

    #[test]
    fn test_try_parse_response_chunked_complete() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let result = try_parse_http1_response(data, 0);
        assert!(result.is_some(), "Should parse complete chunked response");
    }

    #[test]
    fn test_try_parse_response_chunked_incomplete() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(
            try_parse_http1_response(data, 0).is_none(),
            "Should return None for incomplete chunked response"
        );
    }

    // =========================================================================
    // Additional try_parse tests (covering old parse_* functionality)
    // =========================================================================

    #[test]
    fn test_try_parse_request_with_path_and_headers() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let request = try_parse_http1_request(data, 12345).unwrap();

        assert_eq!(request.method, Method::GET);
        assert_eq!(request.uri.path(), "/path");
        assert_eq!(
            request.headers.get("host").unwrap().to_str().unwrap(),
            "example.com"
        );
        assert!(request.body.is_empty());
        assert_eq!(request.timestamp_ns, 12345);
    }

    #[test]
    fn test_try_parse_response_with_content_type() {
        let data =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nHello World";
        let response = try_parse_http1_response(data, 67890).unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
        assert_eq!(response.body, b"Hello World");
        assert_eq!(response.timestamp_ns, 67890);
    }

    #[test]
    fn test_try_parse_response_404() {
        let data = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let response = try_parse_http1_response(data, 0).unwrap();

        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert!(response.body.is_empty());
    }
}
