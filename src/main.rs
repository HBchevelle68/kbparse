// use core::slice::SlicePattern;
// use core::slice::SlicePattern;

use std::env;
use std::fs;
// use std::io::prelude::*;
// use std::io::Cursor;
type BoxedError = Box<dyn std::error::Error>;

#[derive(Default)]
struct KeybagItem {
    tag: String,
    len: u32,
    data: Vec<u8>,
}

impl std::fmt::Debug for KeybagItem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("KeybagItem")
            .field("tag", &self.tag)
            .field("len", &format_args!("{} ({:#02X?})", &self.len, &self.len))
            .field("data", &format_args!("{:02X?}", &self.data))
            .finish()
    }
}
// The Keybag length is the length from the DATA tag, which describes the total
// legnth of what Apple considers the Keybag. It != Total File Size. It doesn't
// consider 36 bytes, of the total data:
//      data_tag(4) + data_len(4) + sig_tag(4) + sig_len(4) + sig(20)
struct Keybag {
    len: u32,
    pos: usize,
    items: Vec<KeybagItem>,
    sig: KeybagItem,
}

const KB_TAG_LEN: usize = 4;
const KB_SZ_LEN: usize = KB_TAG_LEN;
const KB_EXCLUDED_LEN: usize = 36;

impl Keybag {
    fn new(raw: &[u8]) -> Result<Keybag, BoxedError> {
        // Create a mostly default Keybag
        let mut kb = Keybag {
            len: 0,
            pos: 0,
            items: vec![],
            sig: KeybagItem::default(),
        };

        // First tag should always be DATA
        let tag = kb.get_tag(raw)?;
        kb.pos += KB_TAG_LEN;

        // Confirm 'DATA' is first 4 bytes
        match "DATA" == tag {
            true => {
                kb.len = kb.get_tag_len(raw)?;
                kb.pos += KB_SZ_LEN;
            }
            false => return Err("DATA tag not found in bytes provided".into()),
        }

        // Parse Keybag
        // kb.pos is a index to the current position in the raw
        // data. At this point, it's already read 8 bytes, but kb.len
        // does not include those 8 bytes, in order to properly bounds check
        // this loop conditional must consider kb.pos to be 8 bytes behind reality
        while kb.pos - (KB_TAG_LEN + KB_SZ_LEN) != kb.len() {
            let item = kb.get_item(raw)?;
            kb.items.push(item);
        }

        // Get Signature
        // let sigtmp = kb.get_item(raw)?;
        kb.sig = kb.get_item(raw)?;

        Ok(kb)
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.len as usize
    }

    fn get_tag<'a>(&'a self, raw: &'a [u8]) -> Result<String, BoxedError> {
        if self.pos + KB_TAG_LEN < KB_EXCLUDED_LEN + self.len() {
            let tag = std::str::from_utf8(&raw[self.pos..(self.pos + KB_TAG_LEN)])?;
            Ok(tag.to_owned())
        } else {
            Err("Number of bytes requested larger than Keybag size".into())
        }
    }

    fn get_tag_len<'a>(&'a self, raw: &'a [u8]) -> Result<u32, BoxedError> {
        let tlen = u32::from_be_bytes(raw[self.pos..(self.pos + KB_SZ_LEN)].try_into()?);
        Ok(tlen)
    }

    fn get_item(&mut self, raw: &[u8]) -> Result<KeybagItem, BoxedError> {
        let tag = self.get_tag(raw)?;
        self.pos += KB_TAG_LEN;
        let tlen = self.get_tag_len(raw)?;
        self.pos += KB_SZ_LEN;

        let bytes = &raw[self.pos..(self.pos + tlen as usize)];
        self.pos += tlen as usize;
        Ok(KeybagItem {
            tag: tag.to_owned(),
            len: tlen,
            data: bytes.to_vec(),
        })
    }
}

impl std::fmt::Debug for Keybag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Keybag")
            .field("pos", &self.pos)
            .field("len", &self.len)
            .field("items", &self.items)
            .field("signature", &self.sig)
            .finish()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let bytes = fs::read(&args[1])?;

    let kb = Keybag::new(&bytes)?;

    dbg!(&kb);

    Ok(())
}
