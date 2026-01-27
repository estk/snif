use crate::h1;
use h2session::{
    H2ConnectionState, ParseError, ParsedH2Message, is_http2_preface, looks_like_http2_frame,
    parse_frames_stateful,
};
use snif_common::{Data, Kind, MAX_BUF_SIZE};
use std::collections::HashMap;

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
    pub _kind: Kind,
}

/// Tracks state for a single connection
pub struct Connection {
    pub tgid: u32,
    /// Remote port, None if unavailable (e.g., SSL without socket fd)
    pub remote_port: Option<u16>,
    pub protocol: Protocol,
    pub request_chunks: Vec<DataChunk>,
    pub response_chunks: Vec<DataChunk>,
    pub last_activity_ns: u64,
    pub request_complete: bool,
    pub response_complete: bool,

    // Completed messages from h2session, keyed by stream_id
    pending_requests: HashMap<u32, ParsedH2Message>,
    pending_responses: HashMap<u32, ParsedH2Message>,
}

impl Connection {
    pub fn new(tgid: u32, remote_port: u16) -> Self {
        Self {
            tgid,
            // Store None for port 0 (unavailable from SSL)
            remote_port: if remote_port == 0 {
                None
            } else {
                Some(remote_port)
            },
            protocol: Protocol::Unknown,
            request_chunks: Vec::new(),
            response_chunks: Vec::new(),
            last_activity_ns: 0,
            request_complete: false,
            response_complete: false,
            pending_requests: HashMap::new(),
            pending_responses: HashMap::new(),
        }
    }
}

// Re-export HTTP request/response types from h1 module
pub use crate::h1::{HttpRequest, HttpResponse};

/// A complete request/response exchange
#[derive(Debug)]
pub struct Exchange {
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub latency_ns: u64,
    pub protocol: Protocol,
    pub tgid: u32,
    /// Remote port, None if unavailable (e.g., SSL without socket fd)
    pub remote_port: Option<u16>,
    /// Stream ID for HTTP/2 (None for HTTP/1)
    pub stream_id: Option<u32>,
}

impl std::fmt::Display for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto_str = match self.protocol {
            Protocol::Http1 => "HTTP/1.1",
            Protocol::Http2 => "HTTP/2",
            Protocol::Unknown => "Unknown",
        };
        let latency_ms = self.latency_ns as f64 / 1_000_000.0;
        let port_str = self
            .remote_port
            .map_or("unavailable".to_string(), |p| p.to_string());

        writeln!(
            f,
            "=== {} Exchange (PID: {}, Port: {}) ===",
            proto_str, self.tgid, port_str
        )?;
        writeln!(f, "Latency: {:.2}ms", latency_ms)?;
        writeln!(f)?;
        writeln!(f, "--- Request ---")?;
        writeln!(f, "{} {}", self.request.method, self.request.uri)?;
        for (key, value) in &self.request.headers {
            writeln!(f, "{}: {}", key, value.to_str().unwrap_or("<binary>"))?;
        }
        if !self.request.body.is_empty() {
            writeln!(f)?;
            writeln!(f, "{}", String::from_utf8_lossy(&self.request.body))?;
        }
        writeln!(f)?;
        writeln!(f, "--- Response ---")?;
        let reason = self.response.status.canonical_reason().unwrap_or("");
        writeln!(f, "{} {}", self.response.status.as_u16(), reason)?;
        for (key, value) in &self.response.headers {
            writeln!(f, "{}: {}", key, value.to_str().unwrap_or("<binary>"))?;
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
            _kind: data.kind,
        };

        // Use conn_id for socket events, tgid for SSL events
        let conn = if data.conn_id != 0 {
            self.connections
                .entry(data.conn_id)
                .or_insert_with(|| Connection::new(data.tgid, data.peer_port))
        } else {
            self.ssl_connections
                .entry(data.tgid)
                .or_insert_with(|| Connection::new(data.tgid, data.peer_port))
        };

        conn.last_activity_ns = data.timestamp_ns;

        // Update port if we have a non-zero value (SSL events have 0)
        if data.peer_port != 0 && conn.remote_port.is_none() {
            conn.remote_port = Some(data.peer_port);
        }

        // Detect protocol from first chunk if unknown
        if conn.protocol == Protocol::Unknown {
            conn.protocol = detect_protocol(buf);
        }

        // Add chunk to appropriate buffer based on direction
        match data.kind {
            Kind::SslWrite | Kind::SocketWrite => {
                conn.request_chunks.push(chunk);

                // For HTTP/2, parse incrementally
                if conn.protocol == Protocol::Http2 {
                    parse_http2_request_chunks(conn);
                }

                // Check if request is complete
                if is_request_complete(conn) {
                    conn.request_complete = true;
                }
            }
            Kind::SslRead | Kind::SocketRead => {
                conn.response_chunks.push(chunk);

                // For HTTP/2, parse incrementally
                if conn.protocol == Protocol::Http2 {
                    parse_http2_response_chunks(conn);
                }

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
            // For HTTP/1: clear everything
            // For HTTP/2: only the matched pair was removed in build_exchange;
            //             clear chunks but keep remaining pending messages
            conn.request_chunks.clear();
            conn.response_chunks.clear();
            conn.request_complete = false;
            conn.response_complete = false;

            if conn.protocol == Protocol::Http1 {
                conn.protocol = Protocol::Unknown;
            }
            // Note: For HTTP/2, don't clear pending_requests/pending_responses
            //       as they may contain other streams. The matched pair was
            //       already removed in build_exchange().

            return exchange;
        }

        None
    }

    /// Clean up stale connections
    #[allow(dead_code)]
    pub fn cleanup(&mut self, current_time_ns: u64) {
        self.connections
            .retain(|_, conn| current_time_ns - conn.last_activity_ns < self.timeout_ns);
        self.ssl_connections
            .retain(|_, conn| current_time_ns - conn.last_activity_ns < self.timeout_ns);
    }
}

fn detect_protocol(data: &[u8]) -> Protocol {
    // Check for HTTP/2 preface
    if is_http2_preface(data) {
        return Protocol::Http2;
    }

    // Check for HTTP/2 frame header heuristic
    if looks_like_http2_frame(data) {
        return Protocol::Http2;
    }

    // Check for HTTP/1.x request
    if h1::is_http1_request(data) || h1::is_http1_response(data) {
        return Protocol::Http1;
    }

    Protocol::Unknown
}

/// Parse all accumulated request chunks through h2session.
/// Resets parser state on each call to avoid body duplication from re-parsing DATA frames.
fn parse_http2_request_chunks(conn: &mut Connection) {
    let all_data: Vec<u8> = conn
        .request_chunks
        .iter()
        .flat_map(|c| c.data.clone())
        .collect();

    if all_data.is_empty() {
        return;
    }

    // Reset h2 state on each parse to avoid body duplication.
    // When parse_frames_stateful processes DATA frames, it extends stream.body.
    // Re-parsing the same data would extend body again with duplicate data.
    // By resetting state, we parse fresh each time with empty body.
    let mut state = H2ConnectionState::new();

    // Parse and merge completed messages by stream_id
    match parse_frames_stateful(&all_data, &mut state) {
        Ok(messages) => {
            for (stream_id, msg) in messages {
                if msg.is_request() {
                    conn.pending_requests.insert(stream_id, msg);
                }
            }
        }
        Err(ParseError::Http2BufferTooSmall) => {
            // Not enough data yet - normal case
        }
        Err(_) => {
            // Other parse errors - log and continue
        }
    }
}

/// Parse all accumulated response chunks through h2session.
/// Resets parser state on each call to avoid body duplication from re-parsing DATA frames.
fn parse_http2_response_chunks(conn: &mut Connection) {
    let all_data: Vec<u8> = conn
        .response_chunks
        .iter()
        .flat_map(|c| c.data.clone())
        .collect();

    if all_data.is_empty() {
        return;
    }

    // Reset h2 state on each parse to avoid body duplication.
    // See parse_http2_request_chunks for detailed explanation.
    let mut state = H2ConnectionState::new();

    // Parse and merge completed messages by stream_id
    match parse_frames_stateful(&all_data, &mut state) {
        Ok(messages) => {
            for (stream_id, msg) in messages {
                if msg.is_response() {
                    conn.pending_responses.insert(stream_id, msg);
                }
            }
        }
        Err(ParseError::Http2BufferTooSmall) => {
            // Not enough data yet - normal case
        }
        Err(_) => {
            // Other parse errors - log and continue
        }
    }
}

/// Find a stream_id that has both request and response ready
fn find_complete_h2_stream(conn: &Connection) -> Option<u32> {
    conn.pending_requests
        .keys()
        .find(|id| conn.pending_responses.contains_key(id))
        .copied()
}

fn is_request_complete(conn: &Connection) -> bool {
    if conn.request_chunks.is_empty() {
        return false;
    }

    match conn.protocol {
        Protocol::Http1 => {
            let all_data: Vec<u8> = conn
                .request_chunks
                .iter()
                .flat_map(|c| c.data.clone())
                .collect();
            h1::is_http1_message_complete(&all_data)
        }
        Protocol::Http2 => find_complete_h2_stream(conn).is_some(),
        Protocol::Unknown => false,
    }
}

fn is_response_complete(conn: &Connection) -> bool {
    if conn.response_chunks.is_empty() {
        return false;
    }

    match conn.protocol {
        Protocol::Http1 => {
            let all_data: Vec<u8> = conn
                .response_chunks
                .iter()
                .flat_map(|c| c.data.clone())
                .collect();
            h1::is_http1_message_complete(&all_data)
        }
        Protocol::Http2 => find_complete_h2_stream(conn).is_some(),
        Protocol::Unknown => false,
    }
}

fn build_exchange(conn: &mut Connection) -> Option<Exchange> {
    // Use last request chunk timestamp (when request was fully sent)
    // vs first response chunk timestamp (when response started arriving)
    let request_time = conn
        .request_chunks
        .last()
        .map(|c| c.timestamp_ns)
        .unwrap_or(0);
    let response_time = conn
        .response_chunks
        .first()
        .map(|c| c.timestamp_ns)
        .unwrap_or(0);

    let (request, response, stream_id) = match conn.protocol {
        Protocol::Http1 => {
            let request_data: Vec<u8> = conn
                .request_chunks
                .iter()
                .flat_map(|c| c.data.clone())
                .collect();
            let req = h1::parse_http1_request(&request_data, request_time)?;

            let response_data: Vec<u8> = conn
                .response_chunks
                .iter()
                .flat_map(|c| c.data.clone())
                .collect();
            let resp = h1::parse_http1_response(&response_data, response_time)?;

            (req, resp, None)
        }
        Protocol::Http2 => {
            let sid = find_complete_h2_stream(conn)?;
            let msg_req = conn.pending_requests.remove(&sid)?;
            let msg_resp = conn.pending_responses.remove(&sid)?;

            let req = convert_h2_request(&msg_req, request_time)?;
            let resp = convert_h2_response(&msg_resp, response_time)?;

            (req, resp, Some(sid))
        }
        Protocol::Unknown => return None,
    };

    let latency_ns = response_time.saturating_sub(request_time);

    Some(Exchange {
        request,
        response,
        latency_ns,
        protocol: conn.protocol,
        tgid: conn.tgid,
        remote_port: conn.remote_port,
        stream_id,
    })
}

/// Convert a ParsedH2Message to an HttpRequest
fn convert_h2_request(msg: &ParsedH2Message, timestamp_ns: u64) -> Option<HttpRequest> {
    Some(HttpRequest {
        method: msg.http_method()?,
        uri: msg.http_uri()?,
        headers: msg.http_headers(),
        body: msg.body.clone(),
        timestamp_ns,
    })
}

/// Convert a ParsedH2Message to an HttpResponse
fn convert_h2_response(msg: &ParsedH2Message, timestamp_ns: u64) -> Option<HttpResponse> {
    Some(HttpResponse {
        status: msg.http_status()?,
        headers: msg.http_headers(),
        body: msg.body.clone(),
        timestamp_ns,
    })
}
