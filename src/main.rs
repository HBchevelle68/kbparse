use std::env;
use std::fs;

use kbparse::keybag;

// TODO Add cli

// TODO move this to its own crate as a binary crate that depends on the kbparse lib crate

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let bytes = fs::read(&args[1])?;

    let kb = keybag::Keybagv5::new(&bytes)?;

    dbg!(&kb);

    Ok(())
}
