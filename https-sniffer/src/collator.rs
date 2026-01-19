use std::collections::HashMap;
use https_sniffer_common::{Data, Kind, MAX_BUF_SIZE};
use hpack::Decoder;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Protocol detected for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Unknown,
    Http1,
    Http2,
}

/// A chunk of data received from eBPF
#[derive(Debug, Clone)]
pub struct DataChunk {
    pub data: Vec<u8>,
    pub timestamp_ns: u64,
    pub kind: Kind,
}

/// Tracks state for a single connection
#[derive(Debug)]
pub struct Connection {
    pub tgid: u32,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub request_chunks: Vec<DataChunk>,
    pub response_chunks: Vec<DataChunk>,
    pub last_activity_ns: u64,
    pub request_complete: bool,
    pub response_complete: bool,
}

impl Connection {
    pub fn new(tgid: u32, remote_port: u16) -> Self {
        Self {
            tgid,
            remote_port,
            protocol: Protocol::Unknown,
            request_chunks: Vec::new(),
            response_chunks: Vec::new(),
            last_activity_ns: 0,
            request_complete: false,
            response_complete: false,
        }
    }
}

/// A complete HTTP request
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub timestamp_ns: u64,
    pub raw: Vec<u8>,
}

/// A complete HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub timestamp_ns: u64,
    pub raw: Vec<u8>,
}

/// A complete request/response exchange
#[derive(Debug)]
pub struct Exchange {
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub latency_ns: u64,
    pub protocol: Protocol,
    pub tgid: u32,
    pub remote_port: u16,
}

impl std::fmt::Display for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto_str = match self.protocol {
            Protocol::Http1 => "HTTP/1.1",
            Protocol::Http2 => "HTTP/2",
            Protocol::Unknown => "Unknown",
        };
        let latency_ms = self.latency_ns as f64 / 1_000_000.0;

        writeln!(f, "=== {} Exchange (PID: {}, Port: {}) ===", proto_str, self.tgid, self.remote_port)?;
        writeln!(f, "Latency: {:.2}ms", latency_ms)?;
        writeln!(f)?;
        writeln!(f, "--- Request ---")?;
        writeln!(f, "{} {}", self.request.method, self.request.path)?;
        for (key, value) in &self.request.headers {
            writeln!(f, "{}: {}", key, value)?;
        }
        if !self.request.body.is_empty() {
            writeln!(f)?;
            writeln!(f, "{}", String::from_utf8_lossy(&self.request.body))?;
        }
        writeln!(f)?;
        writeln!(f, "--- Response ---")?;
        writeln!(f, "{} {}", self.response.status_code, self.response.status_text)?;
        for (key, value) in &self.response.headers {
            writeln!(f, "{}: {}", key, value)?;
        }
        if !self.response.body.is_empty() {
            writeln!(f)?;
            writeln!(f, "{}", String::from_utf8_lossy(&self.response.body))?;
        }
        Ok(())
    }
}

/// Collates individual data events into complete request/response exchanges
pub struct Collator {
    /// Connections tracked by conn_id (for socket events)
    connections: HashMap<u64, Connection>,
    /// SSL connections tracked by tgid (no conn_id available)
    ssl_connections: HashMap<u32, Connection>,
    /// Connection timeout in nanoseconds (5 seconds)
    timeout_ns: u64,
}

impl Collator {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            ssl_connections: HashMap::new(),
            timeout_ns: 5_000_000_000, // 5 seconds
        }
    }

    /// Add a data event and potentially return a complete exchange
    pub fn add_event(&mut self, data: &Data) -> Option<Exchange> {
        let safe_len = if data.len <= 0 {
            0
        } else if data.len as usize > MAX_BUF_SIZE {
            MAX_BUF_SIZE
        } else {
            data.len as usize
        };

        if safe_len == 0 {
            return None;
        }

        let buf = &data.buf[..safe_len];
        let chunk = DataChunk {
            data: buf.to_vec(),
            timestamp_ns: data.timestamp_ns,
            kind: data.kind,
        };

        // Use conn_id for socket events, tgid for SSL events
        let conn = if data.conn_id != 0 {
            self.connections
                .entry(data.conn_id)
                .or_insert_with(|| Connection::new(data.tgid, data.port))
        } else {
            self.ssl_connections
                .entry(data.tgid)
                .or_insert_with(|| Connection::new(data.tgid, data.port))
        };

        conn.last_activity_ns = data.timestamp_ns;

        // Detect protocol from first chunk if unknown
        if conn.protocol == Protocol::Unknown {
            conn.protocol = detect_protocol(buf);
        }

        // Add chunk to appropriate buffer based on direction
        match data.kind {
            Kind::SslWrite | Kind::SocketWrite => {
                conn.request_chunks.push(chunk);
                // Check if request is complete
                if is_request_complete(conn) {
                    conn.request_complete = true;
                }
            }
            Kind::SslRead | Kind::SocketRead => {
                conn.response_chunks.push(chunk);
                // Check if response is complete
                if is_response_complete(conn) {
                    conn.response_complete = true;
                }
            }
            Kind::SslHandshake => {
                // Handshake events don't contribute to request/response
                return None;
            }
        }

        // If both request and response are complete, emit exchange
        if conn.request_complete && conn.response_complete {
            let exchange = build_exchange(conn);

            // Reset connection for next exchange
            conn.request_chunks.clear();
            conn.response_chunks.clear();
            conn.request_complete = false;
            conn.response_complete = false;
            conn.protocol = Protocol::Unknown;

            return exchange;
        }

        None
    }

    /// Clean up stale connections
    pub fn cleanup(&mut self, current_time_ns: u64) {
        self.connections.retain(|_, conn| {
            current_time_ns - conn.last_activity_ns < self.timeout_ns
        });
        self.ssl_connections.retain(|_, conn| {
            current_time_ns - conn.last_activity_ns < self.timeout_ns
        });
    }
}

fn detect_protocol(data: &[u8]) -> Protocol {
    // Check for HTTP/2 preface
    if data.starts_with(HTTP2_PREFACE) {
        return Protocol::Http2;
    }

    // Check for HTTP/2 frame header
    if data.len() >= 9 {
        let frame_type = data[3];
        if frame_type <= 0x9 {
            let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
            if length <= 16384 {
                return Protocol::Http2;
            }
        }
    }

    // Check for HTTP/1.x request
    if is_http1_request(data) || is_http1_response(data) {
        return Protocol::Http1;
    }

    Protocol::Unknown
}

fn is_http1_request(data: &[u8]) -> bool {
    data.starts_with(b"GET ") ||
    data.starts_with(b"POST ") ||
    data.starts_with(b"PUT ") ||
    data.starts_with(b"DELETE ") ||
    data.starts_with(b"HEAD ") ||
    data.starts_with(b"OPTIONS ") ||
    data.starts_with(b"PATCH ") ||
    data.starts_with(b"CONNECT ")
}

fn is_http1_response(data: &[u8]) -> bool {
    data.starts_with(b"HTTP/1.0") || data.starts_with(b"HTTP/1.1")
}

fn is_request_complete(conn: &Connection) -> bool {
    if conn.request_chunks.is_empty() {
        return false;
    }

    let all_data: Vec<u8> = conn.request_chunks.iter().flat_map(|c| c.data.clone()).collect();

    match conn.protocol {
        Protocol::Http1 => is_http1_message_complete(&all_data),
        Protocol::Http2 => is_http2_request_complete(&all_data),
        Protocol::Unknown => false,
    }
}

fn is_response_complete(conn: &Connection) -> bool {
    if conn.response_chunks.is_empty() {
        return false;
    }

    let all_data: Vec<u8> = conn.response_chunks.iter().flat_map(|c| c.data.clone()).collect();

    match conn.protocol {
        Protocol::Http1 => is_http1_message_complete(&all_data),
        Protocol::Http2 => is_http2_response_complete(&all_data),
        Protocol::Unknown => false,
    }
}

fn is_http1_message_complete(data: &[u8]) -> bool {
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
        if let Some(len_str) = line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")) {
            if let Ok(content_length) = len_str.trim().parse::<usize>() {
                return body.len() >= content_length;
            }
        }
    }

    // Check for Transfer-Encoding: chunked
    if headers.contains("Transfer-Encoding: chunked") || headers.contains("transfer-encoding: chunked") {
        // Look for final chunk (0\r\n\r\n)
        return data.windows(5).any(|w| w == b"0\r\n\r\n");
    }

    // No Content-Length and not chunked - assume complete after headers (e.g., GET request)
    true
}

fn is_http2_request_complete(data: &[u8]) -> bool {
    // For HTTP/2, look for HEADERS frame with END_HEADERS flag (0x04)
    // and optionally DATA frame with END_STREAM flag (0x01)
    let mut offset = 0;

    // Skip preface if present
    if data.starts_with(HTTP2_PREFACE) {
        offset = HTTP2_PREFACE.len();
    }

    let mut has_headers_end = false;

    while offset + 9 <= data.len() {
        let length = ((data[offset] as u32) << 16) | ((data[offset + 1] as u32) << 8) | (data[offset + 2] as u32);
        let frame_type = data[offset + 3];
        let flags = data[offset + 4];

        // HEADERS frame (0x01) with END_STREAM (0x01) or END_HEADERS (0x04)
        if frame_type == 0x01 && (flags & 0x01 != 0 || flags & 0x04 != 0) {
            has_headers_end = true;
        }

        // DATA frame (0x00) with END_STREAM (0x01)
        if frame_type == 0x00 && flags & 0x01 != 0 {
            return true;
        }

        offset += 9 + length as usize;
    }

    has_headers_end
}

fn is_http2_response_complete(data: &[u8]) -> bool {
    // Look for DATA frame with END_STREAM flag, or just any DATA frame with body content
    let mut offset = 0;
    let mut has_data_frame = false;

    while offset + 9 <= data.len() {
        let length = ((data[offset] as u32) << 16) | ((data[offset + 1] as u32) << 8) | (data[offset + 2] as u32);
        let frame_type = data[offset + 3];
        let flags = data[offset + 4];

        // DATA frame (0x00) with END_STREAM (0x01)
        if frame_type == 0x00 && flags & 0x01 != 0 {
            return true;
        }

        // Any DATA frame with content
        if frame_type == 0x00 && length > 0 {
            has_data_frame = true;
        }

        offset += 9 + length as usize;
    }

    // If we have a DATA frame with content, consider it complete
    // This is a heuristic for cases where END_STREAM might be in a separate event
    has_data_frame
}

fn build_exchange(conn: &Connection) -> Option<Exchange> {
    let request_data: Vec<u8> = conn.request_chunks.iter().flat_map(|c| c.data.clone()).collect();
    let response_data: Vec<u8> = conn.response_chunks.iter().flat_map(|c| c.data.clone()).collect();

    // Use last request chunk timestamp (when request was fully sent)
    // vs first response chunk timestamp (when response started arriving)
    let request_time = conn.request_chunks.last().map(|c| c.timestamp_ns).unwrap_or(0);
    let response_time = conn.response_chunks.first().map(|c| c.timestamp_ns).unwrap_or(0);

    let request = match conn.protocol {
        Protocol::Http1 => parse_http1_request(&request_data, request_time)?,
        Protocol::Http2 => parse_http2_request(&request_data, request_time)?,
        Protocol::Unknown => return None,
    };

    let response = match conn.protocol {
        Protocol::Http1 => parse_http1_response(&response_data, response_time)?,
        Protocol::Http2 => parse_http2_response(&response_data, response_time)?,
        Protocol::Unknown => return None,
    };

    let latency_ns = if response_time > request_time {
        response_time - request_time
    } else {
        0
    };

    Some(Exchange {
        request,
        response,
        latency_ns,
        protocol: conn.protocol,
        tgid: conn.tgid,
        remote_port: conn.remote_port,
    })
}

fn parse_http1_request(data: &[u8], timestamp_ns: u64) -> Option<HttpRequest> {
    let s = std::str::from_utf8(data).ok()?;
    let header_end = s.find("\r\n\r\n")?;

    let headers_str = &s[..header_end];
    let body = data[header_end + 4..].to_vec();

    let mut lines = headers_str.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();

    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Some(HttpRequest {
        method,
        path,
        headers,
        body,
        timestamp_ns,
        raw: data.to_vec(),
    })
}

fn parse_http1_response(data: &[u8], timestamp_ns: u64) -> Option<HttpResponse> {
    let s = std::str::from_utf8(data).ok()?;
    let header_end = s.find("\r\n\r\n")?;

    let headers_str = &s[..header_end];
    let body = data[header_end + 4..].to_vec();

    let mut lines = headers_str.lines();
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();

    let _version = parts.next()?;
    let status_code: u16 = parts.next()?.parse().ok()?;
    let status_text: String = parts.collect::<Vec<_>>().join(" ");

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Some(HttpResponse {
        status_code,
        status_text,
        headers,
        body,
        timestamp_ns,
        raw: data.to_vec(),
    })
}

fn parse_http2_request(data: &[u8], timestamp_ns: u64) -> Option<HttpRequest> {
    let mut method = String::from("?");
    let mut path = String::from("?");
    let mut headers = HashMap::new();

    // Try to decode HPACK headers
    let header_blocks = extract_http2_header_blocks(data);
    if !header_blocks.is_empty() {
        let mut decoder = Decoder::new();
        for block in header_blocks {
            if let Ok(decoded_headers) = decoder.decode(&block) {
                for (name, value) in decoded_headers {
                    let name_str = String::from_utf8_lossy(&name).to_string();
                    let value_str = String::from_utf8_lossy(&value).to_string();

                    // Extract pseudo-headers
                    match name_str.as_str() {
                        ":method" => method = value_str.clone(),
                        ":path" => path = value_str.clone(),
                        ":authority" => { headers.insert("Host".to_string(), value_str); continue; }
                        ":scheme" => { headers.insert("Scheme".to_string(), value_str); continue; }
                        _ if name_str.starts_with(':') => continue, // Skip other pseudo-headers
                        _ => {}
                    }
                    headers.insert(name_str, value_str);
                }
            }
        }
    }

    // Add frame info for context
    let frame_info = describe_http2_frames(data);
    if !frame_info.is_empty() {
        headers.insert("_frames".to_string(), frame_info);
    }

    Some(HttpRequest {
        method,
        path,
        headers,
        body: extract_http2_data_payload(data),
        timestamp_ns,
        raw: data.to_vec(),
    })
}

fn parse_http2_response(data: &[u8], timestamp_ns: u64) -> Option<HttpResponse> {
    let mut status_code: u16 = 0;
    let mut status_text = String::new();
    let mut headers = HashMap::new();

    // Try to decode HPACK headers
    let header_blocks = extract_http2_header_blocks(data);
    if !header_blocks.is_empty() {
        let mut decoder = Decoder::new();
        for block in header_blocks {
            if let Ok(decoded_headers) = decoder.decode(&block) {
                for (name, value) in decoded_headers {
                    let name_str = String::from_utf8_lossy(&name).to_string();
                    let value_str = String::from_utf8_lossy(&value).to_string();

                    // Extract pseudo-headers
                    if name_str == ":status" {
                        status_code = value_str.parse().unwrap_or(0);
                        status_text = match status_code {
                            200 => "OK".to_string(),
                            201 => "Created".to_string(),
                            204 => "No Content".to_string(),
                            301 => "Moved Permanently".to_string(),
                            302 => "Found".to_string(),
                            304 => "Not Modified".to_string(),
                            400 => "Bad Request".to_string(),
                            401 => "Unauthorized".to_string(),
                            403 => "Forbidden".to_string(),
                            404 => "Not Found".to_string(),
                            500 => "Internal Server Error".to_string(),
                            502 => "Bad Gateway".to_string(),
                            503 => "Service Unavailable".to_string(),
                            _ => String::new(),
                        };
                        continue;
                    } else if name_str.starts_with(':') {
                        continue; // Skip other pseudo-headers
                    }
                    headers.insert(name_str, value_str);
                }
            }
        }
    }

    // Add frame info for context
    let frame_info = describe_http2_frames(data);
    if !frame_info.is_empty() {
        headers.insert("_frames".to_string(), frame_info);
    }

    Some(HttpResponse {
        status_code,
        status_text,
        headers,
        body: extract_http2_data_payload(data),
        timestamp_ns,
        raw: data.to_vec(),
    })
}

/// Extract header block fragments from HEADERS and CONTINUATION frames
fn extract_http2_header_blocks(data: &[u8]) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    let mut offset = 0;

    // Skip HTTP/2 preface if present
    if data.starts_with(HTTP2_PREFACE) {
        offset = HTTP2_PREFACE.len();
    }

    while offset + 9 <= data.len() {
        let length = ((data[offset] as u32) << 16)
            | ((data[offset + 1] as u32) << 8)
            | (data[offset + 2] as u32);
        let frame_type = data[offset + 3];
        let flags = data[offset + 4];

        let frame_end = offset + 9 + length as usize;
        if frame_end > data.len() {
            break;
        }

        // HEADERS frame (0x01) or CONTINUATION frame (0x09)
        if frame_type == 0x01 || frame_type == 0x09 {
            let mut payload_start = offset + 9;
            let mut payload_end = frame_end;

            // Handle PADDED flag (0x08) - only for HEADERS
            if frame_type == 0x01 && (flags & 0x08) != 0 {
                if payload_start < frame_end {
                    let pad_length = data[payload_start] as usize;
                    payload_start += 1;
                    if payload_end > pad_length {
                        payload_end -= pad_length;
                    }
                }
            }

            // Handle PRIORITY flag (0x20) - only for HEADERS
            if frame_type == 0x01 && (flags & 0x20) != 0 {
                payload_start += 5; // 4 bytes stream dependency + 1 byte weight
            }

            if payload_start < payload_end {
                blocks.push(data[payload_start..payload_end].to_vec());
            }
        }

        offset = frame_end;
    }

    blocks
}

fn describe_http2_frames(data: &[u8]) -> String {
    let mut result = Vec::new();
    let mut offset = 0;

    // Skip preface if present
    if data.starts_with(HTTP2_PREFACE) {
        result.push("PREFACE".to_string());
        offset = HTTP2_PREFACE.len();
    }

    while offset + 9 <= data.len() {
        let length = ((data[offset] as u32) << 16) | ((data[offset + 1] as u32) << 8) | (data[offset + 2] as u32);
        let frame_type = data[offset + 3];
        let flags = data[offset + 4];
        let stream_id = ((data[offset + 5] as u32 & 0x7F) << 24)
            | ((data[offset + 6] as u32) << 16)
            | ((data[offset + 7] as u32) << 8)
            | (data[offset + 8] as u32);

        let frame_name = match frame_type {
            0x0 => "DATA",
            0x1 => "HEADERS",
            0x2 => "PRIORITY",
            0x3 => "RST_STREAM",
            0x4 => "SETTINGS",
            0x5 => "PUSH_PROMISE",
            0x6 => "PING",
            0x7 => "GOAWAY",
            0x8 => "WINDOW_UPDATE",
            0x9 => "CONTINUATION",
            _ => "UNKNOWN",
        };

        result.push(format!("{}(stream={},len={},flags=0x{:02x})", frame_name, stream_id, length, flags));
        offset += 9 + length as usize;

        if offset > data.len() {
            break;
        }
    }

    result.join(", ")
}

fn extract_http2_data_payload(data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut offset = 0;

    while offset + 9 <= data.len() {
        let length = ((data[offset] as u32) << 16) | ((data[offset + 1] as u32) << 8) | (data[offset + 2] as u32);
        let frame_type = data[offset + 3];

        let frame_end = offset + 9 + length as usize;

        // DATA frame (0x00)
        if frame_type == 0x00 && frame_end <= data.len() {
            payload.extend_from_slice(&data[offset + 9..frame_end]);
        }

        offset = frame_end;
    }

    payload
}
