pub mod filter;

// Re-export collator types from http-collator
pub use http_collator::{
    Collator, Connection, DataChunk, DataEvent, Direction, Exchange, HttpRequest, HttpResponse,
    MAX_BUF_SIZE, Protocol,
};

// Re-export h1 parsing utilities
pub mod h1 {
    pub use http_collator::h1::*;
}

// Re-export collator module for backwards compatibility
pub mod collator {
    pub use http_collator::{
        Collator, Connection, DataChunk, Exchange, HttpRequest, HttpResponse, Protocol,
    };
}

use snif_common::{Data, Kind};

/// Implement DataEvent for snif_common::Data
impl DataEvent for Data {
    fn payload(&self) -> &[u8] {
        let safe_len = if self.len <= 0 {
            0
        } else if self.len as usize > MAX_BUF_SIZE {
            MAX_BUF_SIZE
        } else {
            self.len as usize
        };
        &self.buf[..safe_len]
    }

    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn direction(&self) -> Direction {
        match self.kind {
            Kind::SslRead | Kind::SocketRead => Direction::Read,
            Kind::SslWrite | Kind::SocketWrite => Direction::Write,
            Kind::SslHandshake => Direction::Other,
        }
    }

    fn connection_id(&self) -> u64 {
        self.conn_id
    }

    fn process_id(&self) -> u32 {
        self.tgid
    }

    fn remote_port(&self) -> u16 {
        self.peer_port
    }
}
