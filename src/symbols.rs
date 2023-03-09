use std::io::Read;

use crate::Archive;

/// An iterator over the symbols in the symbol table of an archive.
pub struct Symbols<'a, R: 'a + Read> {
    pub(crate) archive: &'a Archive<R>,
    pub(crate) index: usize,
}

impl<'a, R: Read> Iterator for Symbols<'a, R> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ref table) = self.archive.symbol_table {
            if self.index < table.len() {
                let next = table[self.index].0.as_slice();
                self.index += 1;
                return Some(next);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = if let Some(ref table) = self.archive.symbol_table {
            table.len() - self.index
        } else {
            0
        };
        (remaining, Some(remaining))
    }
}

impl<'a, R: Read> ExactSizeIterator for Symbols<'a, R> {}
