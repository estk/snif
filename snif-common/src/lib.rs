// #![no_std]
#![cfg_attr(not(feature = "user"), no_std)]
pub mod data;

pub use data::{ADDR_SIZE, Data, HandshakeEvent, Kind, MAX_BUF_SIZE, TASK_COMM_LEN};
