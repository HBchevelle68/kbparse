use std::env;
use std::fs;

use kbparse::keybag;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let bytes = fs::read(&args[1])?;

    let kb = keybag::Keybag::new(&bytes)?;

    dbg!(&kb);

    Ok(())
}
