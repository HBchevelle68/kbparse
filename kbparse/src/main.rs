use clap::Parser;
use kbparse_lib::keybag;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version = "0.3.0",
    about = "Apple Keybag Parser",
    author = "HBChevelle68"
)]
pub struct KBArgs {
    // #[clap(index = 0)]
    /// Path to Keybag
    pub file: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse args
    let args = KBArgs::parse();

    // Resolve the user provided path, error and return if invaild
    let kb_path = args.file.canonicalize()?;

    let bytes = fs::read(kb_path)?;

    let kb = keybag::Keybagv5::parse(&bytes)?;

    dbg!(&kb);

    Ok(())
}
