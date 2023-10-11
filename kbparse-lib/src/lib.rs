//! This crate provides a lightweight ability to parse Apple _user_ keybags (version 5).
//!
//! ```rust, no_run
//! // Simplified example
//!
//! use kbparse_lib::keybag::Keybagv5;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let args: Vec<String> = std::env::args().collect();
//!     let bytes = std::fs::read(&args[1])?;
//!     let kb = Keybagv5::parse(&bytes)?;
//!     println!("{:#?}", kb);
//!     dbg!(&kb);
//!     Ok(())
//! }
//! ```
//!

pub mod keybag;
