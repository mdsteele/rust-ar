use std::cmp;
use std::io::{self, Error, ErrorKind, Read, Result, Seek, SeekFrom};

use crate::header::Header;

/// Representation of an archive entry.
///
/// `Entry` objects implement the `Read` trait, and can be used to extract the
/// data from this archive entry.  If the underlying reader supports the `Seek`
/// trait, then the `Entry` object supports `Seek` as well.
pub struct Entry<'a, R: 'a + Read> {
    pub(crate) header: &'a Header,
    pub(crate) reader: &'a mut R,
    pub(crate) length: u64,
    pub(crate) position: u64,
}

impl<'a, R: 'a + Read> Entry<'a, R> {
    /// Returns the header for this archive entry.
    pub fn header(&self) -> &Header {
        self.header
    }
}

impl<'a, R: 'a + Read> Read for Entry<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        debug_assert!(self.position <= self.length);
        if self.position == self.length {
            return Ok(0);
        }
        let max_len =
            cmp::min(self.length - self.position, buf.len() as u64) as usize;
        let bytes_read = self.reader.read(&mut buf[0..max_len])?;
        self.position += bytes_read as u64;
        debug_assert!(self.position <= self.length);
        Ok(bytes_read)
    }
}

impl<'a, R: 'a + Read + Seek> Seek for Entry<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let delta = match pos {
            SeekFrom::Start(offset) => offset as i64 - self.position as i64,
            SeekFrom::End(offset) => {
                self.length as i64 + offset - self.position as i64
            }
            SeekFrom::Current(delta) => delta,
        };
        let new_position = self.position as i64 + delta;
        if new_position < 0 {
            let msg = format!(
                "Invalid seek to negative position ({})",
                new_position
            );
            return Err(Error::new(ErrorKind::InvalidInput, msg));
        }
        let new_position = new_position as u64;
        if new_position > self.length {
            let msg = format!(
                "Invalid seek to position past end of entry ({} vs. {})",
                new_position, self.length
            );
            return Err(Error::new(ErrorKind::InvalidInput, msg));
        }
        self.reader.seek(SeekFrom::Current(delta))?;
        self.position = new_position;
        Ok(self.position)
    }
}

impl<'a, R: 'a + Read> Drop for Entry<'a, R> {
    fn drop(&mut self) {
        if self.position < self.length {
            // Consume the rest of the data in this entry.
            let mut remaining = self.reader.take(self.length - self.position);
            let _ = io::copy(&mut remaining, &mut io::sink());
        }
    }
}
