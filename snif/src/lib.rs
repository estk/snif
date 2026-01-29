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
