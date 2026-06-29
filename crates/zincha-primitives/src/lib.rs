#![allow(dead_code)]

//! Public client-safe Zincha primitives.

pub mod config;
pub mod crypto;
pub mod embedding;
pub mod error;
pub mod primitives;
pub mod release;
pub mod wallet;

pub use error::{Result, ZinchaError};
