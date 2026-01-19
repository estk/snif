// https://datatracker.ietf.org/doc/html/rfc6066#section-4
// https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html
pub const MAX_BUF_SIZE: usize = 16384;
pub const TASK_COMM_LEN: usize = 16;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    SslRead = 0,
    SslWrite = 1,
    SocketRead = 2,
    SocketWrite = 3,
    SslHandshake = 4,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Data {
    pub kind: Kind,
    pub len: i32,
    pub conn_id: u64,        // Connection identifier (hash of pid + ports)
    pub timestamp_ns: u64,   // Kernel timestamp from bpf_ktime_get_ns()
    pub tgid: u32,           // Process ID for connection tracking
    pub port: u16,           // Foreign (remote) port, 0 if unknown
    pub local_port: u16,     // Local port (server's listening port), 0 if unknown
    pub buf: [u8; MAX_BUF_SIZE],
    pub comm: [u8; TASK_COMM_LEN],
}

/// Handshake event data - emitted when SSL_do_handshake completes
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeEvent {
    pub kind: Kind,              // Always SslHandshake
    pub success: i32,            // 1 if handshake succeeded, 0 or negative if failed
    pub duration_ns: u64,        // Time spent in handshake
    pub tgid: u32,               // Process ID
    pub _pad: u32,               // Padding for alignment
    pub comm: [u8; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[cfg(feature = "user")]
fn http2_frame_type_name(frame_type: u8) -> &'static str {
    match frame_type {
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
    }
}

#[cfg(feature = "user")]
fn parse_http2_frames(data: &[u8]) -> Option<String> {
    let mut result = String::new();
    let mut offset = 0;

    // Check for HTTP/2 connection preface
    if data.starts_with(HTTP2_PREFACE) {
        result.push_str("[HTTP/2 Preface] ");
        offset = HTTP2_PREFACE.len();
    }

    // Parse frames
    while offset + 9 <= data.len() {
        // Frame header: 3 bytes length, 1 byte type, 1 byte flags, 4 bytes stream ID
        let length = ((data[offset] as u32) << 16)
            | ((data[offset + 1] as u32) << 8)
            | (data[offset + 2] as u32);
        let frame_type = data[offset + 3];
        let flags = data[offset + 4];
        let stream_id = ((data[offset + 5] as u32 & 0x7F) << 24)
            | ((data[offset + 6] as u32) << 16)
            | ((data[offset + 7] as u32) << 8)
            | (data[offset + 8] as u32);

        let frame_name = http2_frame_type_name(frame_type);
        result.push_str(&format!(
            "[{} stream={} len={} flags=0x{:02x}] ",
            frame_name, stream_id, length, flags
        ));

        let frame_end = offset + 9 + length as usize;

        // For DATA frames, try to show the payload
        if frame_type == 0x0 && frame_end <= data.len() {
            let payload = &data[offset + 9..frame_end];
            let payload_str = String::from_utf8_lossy(payload);
            result.push_str(&format!("{}", payload_str));
        }

        offset = frame_end;
        if offset > data.len() {
            break;
        }
    }

    // If we have remaining data after frames, show it
    if offset < data.len() {
        let remaining = &data[offset..];
        let remaining_str = String::from_utf8_lossy(remaining);
        if !remaining_str.trim().is_empty() {
            result.push_str(&format!("{}", remaining_str));
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(feature = "user")]
fn is_likely_http2(data: &[u8]) -> bool {
    // Check for HTTP/2 preface
    if data.starts_with(HTTP2_PREFACE) {
        return true;
    }
    // Check if it looks like an HTTP/2 frame header
    // Frame header is 9 bytes, and we can validate the frame type
    if data.len() >= 9 {
        let frame_type = data[3];
        // Valid frame types are 0x0-0x9
        if frame_type <= 0x9 {
            let length = ((data[0] as u32) << 16)
                | ((data[1] as u32) << 8)
                | (data[2] as u32);
            // Sanity check: frame length should be reasonable
            if length <= 16384 {
                return true;
            }
        }
    }
    false
}

#[cfg(feature = "user")]
impl std::fmt::Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let comm_str = String::from_utf8_lossy(&self.comm);
        // Safely bound the length to avoid panics
        let safe_len = if self.len <= 0 {
            0
        } else if self.len as usize > MAX_BUF_SIZE {
            MAX_BUF_SIZE
        } else {
            self.len as usize
        };
        let buf = &self.buf[..safe_len];

        let kind_str = match self.kind {
            Kind::SslRead => "SSL Read",
            Kind::SslWrite => "SSL Write",
            Kind::SocketRead => "Socket Read",
            Kind::SocketWrite => "Socket Write",
            Kind::SslHandshake => "SSL Handshake",
        };

        let port_str = if self.port > 0 {
            format!("{}", self.port)
        } else {
            "unknown".to_string()
        };

        let local_port_str = if self.local_port > 0 {
            format!("{}", self.local_port)
        } else {
            "unknown".to_string()
        };

        // Try to parse as HTTP/2 for SSL traffic
        let data_str = if matches!(self.kind, Kind::SslRead | Kind::SslWrite) && is_likely_http2(buf) {
            parse_http2_frames(buf).unwrap_or_else(|| String::from_utf8_lossy(buf).to_string())
        } else {
            String::from_utf8_lossy(buf).to_string()
        };

        write!(
            f,
            "Kind: {}, LocalPort: {}, RemotePort: {}, Length: {}, Command: {}, Data: {}",
            kind_str, local_port_str, port_str, self.len, comm_str, data_str
        )
    }
}

#[cfg(feature = "user")]
impl std::fmt::Display for HandshakeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let comm_str = String::from_utf8_lossy(&self.comm);
        let status = if self.success > 0 { "success" } else { "failed" };
        let duration_ms = self.duration_ns as f64 / 1_000_000.0;

        write!(
            f,
            "SSL Handshake: {}, Duration: {:.2}ms, PID: {}, Command: {}",
            status, duration_ms, self.tgid, comm_str
        )
    }
}
