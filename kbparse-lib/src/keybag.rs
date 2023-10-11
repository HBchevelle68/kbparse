type BoxedError = Box<dyn std::error::Error>;

// use scroll::{Pread, BE};

// TODO move this into its own lib crate

#[derive(Default)]
pub struct Keybagv5ClassKey {
    uuid: Keybagv5Item,
    class: Keybagv5Item,
    key_type: Keybagv5Item,
    wrap: Keybagv5Item,
    wrapped_key: Keybagv5Item,
    pbky: Option<Keybagv5Item>,
}
impl std::fmt::Debug for Keybagv5ClassKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Keybagv5Item")
            .field("UUID", &self.uuid)
            .field("Key Class", &self.class)
            .field("Key Type", &self.key_type)
            .field("Wrap", &self.wrap)
            .field("Wrapped Key", &self.wrapped_key)
            .field("PBKY", &self.pbky)
            .finish()
    }
}

#[derive(Default)]
pub struct Keybagv5Metadata {
    uuid: Keybagv5Item,
    hmac: Keybagv5Item,
    wrap: Keybagv5Item,
    salt: Keybagv5Item,
    iter: Keybagv5Item,
    grce: Keybagv5Item,
    cfgf: Keybagv5Item,
    tkmt: Keybagv5Item,
    usid: Keybagv5Item,
    grid: Keybagv5Item,
}
impl std::fmt::Debug for Keybagv5Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Keybagv5Item")
            .field("UUID", &self.uuid)
            .field("HMAC", &self.hmac)
            .field("WRAP", &self.wrap)
            .field("SALT", &self.salt)
            .field("ITER", &self.iter)
            .field("GRCE", &self.grce)
            .field("CFGF", &self.cfgf)
            .field("TKMT", &self.tkmt)
            .field("USID", &self.usid)
            .field("GRID", &self.grid)
            .finish()
    }
}

#[derive(Default, Clone)]
pub struct Keybagv5Item {
    tag: String,
    len: u32,
    data: Vec<u8>,
}

impl Keybagv5Item {
    fn data_as_u32(&self) -> Result<u32, BoxedError> {
        if self.len > 4 {
            // Too large
            Err(format!("Data length [{}] is too large to convert to u32", self.len).into())
        } else {
            let tmp = self.data.as_slice();
            Ok(u32::from_be_bytes(tmp.try_into()?))
        }
    }
}

impl std::fmt::Debug for Keybagv5Item {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Keybagv5Item")
            .field("tag", &self.tag)
            .field("len", &format_args!("{} ({:#02X?})", &self.len, &self.len))
            .field("data", &format_args!("{:02X?}", &self.data))
            .finish()
    }
}

const KB_TAG_LEN: usize = 4;
const KB_SZ_LEN: usize = KB_TAG_LEN;
const KB_EXCLUDED_LEN: usize = 36;

/// The Keybag length is the length from the DATA tag, which describes the total
/// legnth of what Apple considers the Keybag. It != Total File Size. It doesn't
/// consider 36 bytes, of the total data:
///      data_tag(4) + data_len(4) + sig_tag(4) + sig_len(4) + sig(20)
#[derive(Default)]
pub struct Keybagv5 {
    pos: usize,
    pub len: u32,
    pub kb_type: Keybagv5Item,
    pub kb_vers: Keybagv5Item,
    pub metadata: Keybagv5Metadata,
    pub class_keys: Vec<Keybagv5ClassKey>,
    pub sig: Keybagv5Item,
}

impl Keybagv5 {
    pub fn parse(raw: &[u8]) -> Result<Keybagv5, BoxedError> {
        // Create a base default Keybag
        let mut kb = Keybagv5::default();

        // First tag should always be DATA
        // Only pull the tag and len, the actual
        // data is the rest of the bag
        let tag = kb.parse_tag(raw)?;
        kb.pos += KB_TAG_LEN;

        // Confirm 'DATA' is first 4 bytes
        // Using this to essentially say "OK this is a Apple keybag"
        match "DATA" == tag {
            true => {
                kb.len = kb.parse_tag_len(raw)?;
                kb.pos += KB_SZ_LEN;
            }
            false => return Err("DATA tag not found in bytes provided".into()),
        }

        kb.kb_vers = kb.parse_item(raw)?;
        if kb.get_vers()? != 5 {
            let msg = format!(
                "Only Keybag version 5 supported. Version {} found...",
                kb.get_vers()?
            );
            return Err(msg.into());
        }

        kb.kb_type = kb.parse_item(raw)?;
        // TODO confirm bag type?

        // Parse Metadata
        let item_meta_uuid = kb.parse_item(raw)?;
        kb.metadata = Keybagv5Metadata {
            uuid: item_meta_uuid,
            hmac: kb.parse_item(raw)?,
            wrap: kb.parse_item(raw)?,
            salt: kb.parse_item(raw)?,
            iter: kb.parse_item(raw)?,
            grce: kb.parse_item(raw)?,
            cfgf: kb.parse_item(raw)?,
            tkmt: kb.parse_item(raw)?,
            usid: kb.parse_item(raw)?,
            grid: kb.parse_item(raw)?,
        };

        // Parse class keys
        // `pos` is the read position within the raw data. When the `DATA`
        // tag was parsed and its `len` retrieved, that length doesn't account for
        // the 8 bytes tht had to be parsed to get there but the _keybag length_
        // accounts for all bytes in the file. The conditional needs to account
        // for these 8 bytes to be accurate
        while kb.pos - (KB_TAG_LEN + KB_SZ_LEN) != kb.get_len() {
            let ck = kb.parse_key_class(raw)?;
            kb.class_keys.push(ck);
        }

        // Get Signature
        kb.sig = kb.parse_item(raw)?;

        Ok(kb)
    }

    #[inline(always)]
    /// Returns the total size of the parsed user keybag
    pub fn get_len(&self) -> usize {
        self.len as usize
    }

    /// Returns the version of the parsed keybag as a u32
    pub fn get_vers(&self) -> Result<u32, BoxedError> {
        self.kb_vers.data_as_u32()
    }

    /// Returns the type of the parsed keybag as a u32
    /// <https://support.apple.com/guide/security/keybags-for-data-protection-sec6483d5760/web>
    pub fn get_type(&self) -> Result<u32, BoxedError> {
        self.kb_type.data_as_u32()
    }

    // A wrapper around parse_tag() to express intent
    #[inline(always)]
    fn peek_tag<'a>(&'a self, raw: &'a [u8]) -> Result<String, BoxedError> {
        self.parse_tag(raw)
    }

    fn parse_tag<'a>(&'a self, raw: &'a [u8]) -> Result<String, BoxedError> {
        if self.pos + KB_TAG_LEN < KB_EXCLUDED_LEN + self.get_len() {
            let tag = std::str::from_utf8(&raw[self.pos..(self.pos + KB_TAG_LEN)])?;
            Ok(tag.to_owned())
        } else {
            Err("Number of bytes requested larger than Keybag size".into())
        }
    }

    fn parse_tag_len<'a>(&'a self, raw: &'a [u8]) -> Result<u32, BoxedError> {
        if self.pos + KB_TAG_LEN < KB_EXCLUDED_LEN + self.get_len() {
            Ok(u32::from_be_bytes(
                raw[self.pos..(self.pos + KB_SZ_LEN)].try_into()?,
            ))
        } else {
            Err("Number of bytes requested larger than Keybag size".into())
        }
    }

    fn parse_item(&mut self, raw: &[u8]) -> Result<Keybagv5Item, BoxedError> {
        // println!("parse_item: pos:{:#?}", self.pos);
        let tag = self.parse_tag(raw)?;
        self.pos += KB_TAG_LEN;
        let tlen = self.parse_tag_len(raw)?;
        self.pos += KB_SZ_LEN;

        // Need to be <=, as last item should read up to the final byte
        if (self.pos + tlen as usize) <= KB_EXCLUDED_LEN + self.get_len() {
            let bytes = &raw[self.pos..(self.pos + tlen as usize)];
            self.pos += tlen as usize;

            // TODO
            // Maybe find a way to not require the copy??
            Ok(Keybagv5Item {
                tag: tag.to_owned(),
                len: tlen,
                data: bytes.to_vec(),
            })
        } else {
            Err("Number of bytes requested larger than Keybag size".into())
        }
    }

    fn parse_key_class(&mut self, raw: &[u8]) -> Result<Keybagv5ClassKey, BoxedError> {
        Ok(Keybagv5ClassKey {
            uuid: self.parse_item(raw)?,
            class: self.parse_item(raw)?,
            key_type: self.parse_item(raw)?,
            wrap: self.parse_item(raw)?,
            wrapped_key: self.parse_item(raw)?,
            // Not all class key items have a pbky item
            pbky: if "PBKY" == self.peek_tag(raw)? {
                Some(self.parse_item(raw)?)
            } else {
                None
            },
        })
    }
}

impl std::fmt::Debug for Keybagv5 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Keybag")
            .field("pos", &self.pos)
            .field("len", &self.len)
            .field("KB Version", &self.kb_vers)
            .field("KB Type", &self.kb_type)
            .field("KB Metadata", &self.metadata)
            .field("KB Class Keys", &self.class_keys)
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

        assert_eq!(true, super::Keybagv5::parse(&test_file_data).is_err());
    }

    #[test]
    fn bounds_check_parse_tag() {
        let mut bad_kb = super::Keybagv5::default();
        // parse_tag account for 36 bytes not considered part of length
        // negate that by setting this to 36
        bad_kb.pos = 36;
        bad_kb.len = 3;

        let test_file_data = [0x2F, 0xCD, 0xCE];

        assert_eq!(true, bad_kb.parse_tag(&test_file_data).is_err());
    }

    #[test]
    fn bounds_check_parse_tag_len() {
        let mut bad_kb = super::Keybagv5::default();
        // parse_tag account for 36 bytes not considered part of length
        // negate that by setting this to 36
        bad_kb.pos = 36;
        bad_kb.len = 3;

        let test_file_data = [0x2F, 0xCD, 0xCE];

        assert_eq!(true, bad_kb.parse_tag_len(&test_file_data).is_err());
    }

    #[test]
    fn bounds_check_parse_item_bad_length() {
        let mut bad_kb = super::Keybagv5::default();
        // parse_tag account for 36 bytes not considered part of length
        // negate that by setting this to 36
        bad_kb.pos = 36;
        bad_kb.len = 12;

        // 0x00 * 36 to account for fake pos
        // Fake tag of 'DATA'
        // Size should be 0xff000000 (4278190080)
        // parse_item should catch the bad length
        let test_file_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x41, 0x54, 0x41, 0xFF, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        assert_eq!(true, bad_kb.parse_item(&test_file_data).is_err());
    }
}
