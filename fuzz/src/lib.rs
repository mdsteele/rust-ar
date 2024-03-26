use arbitrary::{Arbitrary, Unstructured};

#[derive(Clone, Default, Debug, Eq, PartialEq, Arbitrary)]
pub struct Model {
    pub entries: Vec<Entry>,
}

impl Model {
    pub fn identifiers(&self) -> Vec<Vec<u8>> {
        self.entries.iter().map(|e| e.header.identifier.0.clone()).collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Arbitrary)]
pub struct Entry {
    pub header: Header,
    pub data: Vec<u8>,
}

impl Entry {
    pub fn header(&self) -> ar::Header {
        let mut header = ar::Header::new(
            self.header.identifier.0.clone(),
            self.data.len() as u64,
        );
        header.set_mtime(self.header.mtime.0);
        header.set_uid(self.header.uid.0);
        header.set_gid(self.header.gid.0);
        header.set_mode(self.header.mode.0);
        header
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Arbitrary)]
pub struct Header {
    identifier: Identifier,
    mtime: Timestamp,
    uid: Uid,
    gid: Uid,
    mode: Mode,
}

impl Header {
    pub fn from_ar(header: &ar::Header) -> Header {
        Header {
            identifier: Identifier(header.identifier().to_vec()),
            mtime: Timestamp(header.mtime()),
            uid: Uid(header.uid()),
            gid: Uid(header.gid()),
            mode: Mode(header.mode()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identifier(Vec<u8>);

impl Arbitrary<'_> for Identifier {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        // TODO: Reject invalid identifiers at creation time:
        // - Long identifiers
        // - Invalid ASCII or invalid UTF-8?
        // - Containing NUL
        // - Rules for '/'?
        // - Rules for spaces?
        String::arbitrary(u).map(|mut v| {
            v.retain(|ch| ch != '\0' && ch != '/' && ch != ' ');
            while v.len() > 15 {
                v.pop();
            }
            if v.is_empty() {
                v.push('a');
            }
            Identifier(v.into_bytes())
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Mode(u32);

impl Arbitrary<'_> for Mode {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        u32::arbitrary(u).map(|v| Mode(v & 0o7777))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Timestamp(u64);

impl Arbitrary<'_> for Timestamp {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        u.int_in_range(0..=999_999_999_999).map(Timestamp) // TODO: Deal with entire range
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Uid(u32);

impl Arbitrary<'_> for Uid {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        u.int_in_range(0..=999_999).map(Uid) // TODO: Deal with entire range (#29)
    }
}
