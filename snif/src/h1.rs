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

/// Check if an HTTP/1.x message is complete
pub fn is_http1_message_complete(data: &[u8]) -> bool {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Find end of headers
    let header_end = match s.find("\r\n\r\n") {
        Some(pos) => pos + 4,
        None => return false, // Headers not complete
    };

    let headers = &s[..header_end];
    let body = &data[header_end..];

    // Check for Content-Length
    for line in headers.lines() {
        if let Some(len_str) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
            && let Ok(content_length) = len_str.trim().parse::<usize>()
        {
            return body.len() >= content_length;
        }
    }

    // Check for Transfer-Encoding: chunked
    if headers.contains("Transfer-Encoding: chunked")
        || headers.contains("transfer-encoding: chunked")
    {
        // Look for final chunk (0\r\n\r\n)
        return data.windows(5).any(|w| w == b"0\r\n\r\n");
    }

    // No Content-Length and not chunked - assume complete after headers (e.g., GET request)
    true
}

/// Parse HTTP/1.x request data into an HttpRequest
pub fn parse_http1_request(data: &[u8], timestamp_ns: u64) -> Option<HttpRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let body_offset = match req.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        _ => return None,
    };

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
        body: data[body_offset..].to_vec(),
        timestamp_ns,
    })
}

/// Parse HTTP/1.x response data into an HttpResponse
pub fn parse_http1_response(data: &[u8], timestamp_ns: u64) -> Option<HttpResponse> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);

    let body_offset = match res.parse(data) {
        Ok(httparse::Status::Complete(len)) => len,
        _ => return None,
    };

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
        body: data[body_offset..].to_vec(),
        timestamp_ns,
    })
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

    #[test]
    fn test_is_http1_message_complete_no_body() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(is_http1_message_complete(request));
    }

    #[test]
    fn test_is_http1_message_complete_with_content_length() {
        let request = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert!(is_http1_message_complete(request));

        let incomplete = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhello";
        assert!(!is_http1_message_complete(incomplete));
    }

    #[test]
    fn test_is_http1_message_complete_chunked() {
        let chunked =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(is_http1_message_complete(chunked));

        let incomplete_chunked =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(!is_http1_message_complete(incomplete_chunked));
    }

    #[test]
    fn test_is_http1_message_incomplete_headers() {
        let incomplete = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(!is_http1_message_complete(incomplete));
    }

    #[test]
    fn test_parse_http1_request() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let request = parse_http1_request(data, 12345).unwrap();

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
    fn test_parse_http1_request_with_body() {
        let data = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let request = parse_http1_request(data, 0).unwrap();

        assert_eq!(request.method, Method::POST);
        assert_eq!(request.body, b"hello");
    }

    #[test]
    fn test_parse_http1_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World";
        let response = parse_http1_response(data, 67890).unwrap();

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
    fn test_parse_http1_response_404() {
        let data = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let response = parse_http1_response(data, 0).unwrap();

        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert!(response.body.is_empty());
    }
}
