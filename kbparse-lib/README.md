# kbparse-lib

This crate provides a lightweight ability to parse Apple _user_ keybags (version 5). This crate has no dependencies other than std.


```rust
// Simplified example
use kbparse_lib::keybag;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&args[1])?;
    let kb = keybag::Keybagv5::parse(&bytes)?;
    println!("{:#?}", kb);
    Ok(())
}
```
## Platform Support
- macOS-14-aarch64 (arm64e)
- macOS-13-aarch64 (arm64e)
- macOS-13-x86_64
- macOS-12-x86_64
- macOS-12-aarch64 (arm64e)
- macOS-11-x86_64

# Toolchain Support
- aarch64-apple-darwin
- x86_64-apple-darwin
