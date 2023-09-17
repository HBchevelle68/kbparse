type BoxedError = Box<dyn std::error::Error>;

// use scroll::{Pread, BE};

#[derive(Default, Clone)]
pub struct KeybagItem {
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

const KB_TAG_LEN: usize = 4;
const KB_SZ_LEN: usize = KB_TAG_LEN;
const KB_EXCLUDED_LEN: usize = 36;

// The Keybag length is the length from the DATA tag, which describes the total
// legnth of what Apple considers the Keybag. It != Total File Size. It doesn't
// consider 36 bytes, of the total data:
//      data_tag(4) + data_len(4) + sig_tag(4) + sig_len(4) + sig(20)
#[derive(Default)]
pub struct Keybag {
    pos: usize,
    pub len: u32,
    pub kb_type: KeybagItem,
    pub kb_vers: KeybagItem,
    pub items: Vec<KeybagItem>,
    pub sig: KeybagItem,
}

impl Keybag {
    pub fn new(raw: &[u8]) -> Result<Keybag, BoxedError> {
        // Create a base default Keybag
        let mut kb = Keybag::default();

        // First tag should always be DATA
        let tag = kb.get_tag(raw)?;
        kb.pos += KB_TAG_LEN;

        // Confirm 'DATA' is first 4 bytes
        // Using this to essentially say "OK this is a Apple keybag"
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
            match item.tag.as_str() {
                "TYPE" => {
                    kb.kb_type = item;
                }
                "VERS" => {
                    kb.kb_vers = item;
                }
                _ => {
                    kb.items.push(item);
                }
            }
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
        if self.pos + KB_TAG_LEN < KB_EXCLUDED_LEN + self.len() {
            let tlen = u32::from_be_bytes(raw[self.pos..(self.pos + KB_SZ_LEN)].try_into()?);
            // let tlen = raw.pread_with::<u32>(self.pos, BE)?;
            Ok(tlen)
        } else {
            Err("Number of bytes requested larger than Keybag size".into())
        }
    }

    fn get_item(&mut self, raw: &[u8]) -> Result<KeybagItem, BoxedError> {
        let tag = self.get_tag(raw)?;
        self.pos += KB_TAG_LEN;
        let tlen = self.get_tag_len(raw)?;
        self.pos += KB_SZ_LEN;
        // Need to be <=, as last item should read up to the final byte
        if (self.pos + tlen as usize) <= KB_EXCLUDED_LEN + self.len() {
            let bytes = &raw[self.pos..(self.pos + tlen as usize)];
            self.pos += tlen as usize;
            Ok(KeybagItem {
                tag: tag.to_owned(),
                len: tlen,
                data: bytes.to_vec(),
            })
        } else {
            Err("Number of bytes requested larger than Keybag size".into())
        }
    }
}

impl std::fmt::Debug for Keybag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Keybag")
            .field("pos", &self.pos)
            .field("len", &self.len)
            .field("KB Version", &self.kb_vers)
            .field("KB Type", &self.kb_type)
            .field("KB items", &self.items)
            .field("KB signature", &self.sig)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_keybag_file() {
        let test_file_data = [
            0x2F, 0xCD, 0xCE, 0xDB, 0xE9, 0x99, 0x4B, 0xA4, 0xAD, 0x38, 0x9C, 0x59, 0x31, 0x25,
            0x43, 0x5F,
        ];

        assert_eq!(true, super::Keybag::new(&test_file_data).is_err());
    }

    #[test]
    fn bounds_check_get_tag() {
        let mut bad_kb = super::Keybag::default();
        // get_tag account for 36 bytes not considered part of length
        // negate that by setting this to 36
        bad_kb.pos = 36;
        bad_kb.len = 3;

        let test_file_data = [0x2F, 0xCD, 0xCE];

        assert_eq!(true, bad_kb.get_tag(&test_file_data).is_err());
    }

    #[test]
    fn bounds_check_get_tag_len() {
        let mut bad_kb = super::Keybag::default();
        // get_tag account for 36 bytes not considered part of length
        // negate that by setting this to 36
        bad_kb.pos = 36;
        bad_kb.len = 3;

        let test_file_data = [0x2F, 0xCD, 0xCE];

        assert_eq!(true, bad_kb.get_tag_len(&test_file_data).is_err());
    }

    #[test]
    fn bounds_check_get_item_bad_length() {
        let mut bad_kb = super::Keybag::default();
        // get_tag account for 36 bytes not considered part of length
        // negate that by setting this to 36
        bad_kb.pos = 36;
        bad_kb.len = 12;

        // 0x00 * 36 to account for fake pos
        // Fake tag of 'DATA'
        // Size should be 0xff000000 (4278190080)
        // get_item should catch the bad length
        let test_file_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x41, 0x54, 0x41, 0xFF, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        assert_eq!(true, bad_kb.get_item(&test_file_data).is_err());
    }
}
