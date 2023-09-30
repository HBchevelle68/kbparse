//! This crate provides a lightweight ability to parse Apple _user_ keybags (version 5).
//!
//! ```rust
//! // Simplified example
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let args: Vec<String> = env::args().collect();
//!     let bytes = fs::read(&args[1])?;
//!     let kb = keybag::Keybagv5::new(&bytes)?;
//!     println!("{:#?}", kb);
//!     dbg!(&kb);
//!     Ok(())
//! }
//! ```
//!

pub mod keybag;
