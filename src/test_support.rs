//! Test utils for rust-ar, typically `Arbitrary` implementations of things
use super::*;

use proptest::{
    arbitrary::Arbitrary,
    collection::vec,
    prelude::*
};

/// Arbitrary implementation of Header and Data for feeding into tests
#[derive(Debug, Clone)]
pub struct HeaderAndData {
    /// The header generated for this case
    pub header: Header,
    /// The data for this case
    pub data: Vec<u8>,
}

impl Arbitrary for HeaderAndData {
    type Parameters = bool;
    type Strategy = BoxedStrategy<Self>;

    /// Produces arbitrary archives for testing
    ///
    /// **Note:** very tecnically its possible to have `/` and spaces in archive names for
    /// different permutations of BSD and GNU archives. We dont test these because the corner case
    /// is very subtle and most tools do not deal well with archives that have such strange names.
    fn arbitrary_with(deterministic: Self::Parameters) -> Self::Strategy {
        if deterministic {
            (
                vec(any::<u8>(), 0..65 * 1024), // Data
                r#"[\PC&&[^/[:blank:]]]{1,50}"#, // Ident
            )
                .prop_map(|(data, ident)| {
                    HeaderAndData {
                        header: Header::new(&ident, data.len() as u64),
                        data
                    }
                })
                .boxed()
        } else {
            (
                vec(any::<u8>(), 0..65 * 1024), // Data
                r#"[\PC&&[^/[:blank:]]]{1,50}"#, // Ident
                0..999999999999u64, // Mtime
                0..999999u32, // Uid
                0..999999u32, // Gid
                0..342391u32, // Mode
            )
                .prop_map(|(data, ident, mtime, uid, gid, mode)| {
                    let size = data.len() as u64;
                    let identifier = Ident::from_slice(ident.as_bytes());
                    let header = Header { identifier, mtime, uid, gid, mode, size };
                    HeaderAndData { header, data }
                })
                .boxed()
        }
    }
}
