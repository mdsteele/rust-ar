use std::collections::HashMap;
use std::fs::Metadata;
use std::io::{self, Error, ErrorKind, Read, Result, Write};
use std::str;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::archive::{
    Variant, BSD_SORTED_SYMBOL_LOOKUP_TABLE_ID, BSD_SYMBOL_LOOKUP_TABLE_ID,
    GNU_NAME_TABLE_ID, GNU_SYMBOL_LOOKUP_TABLE_ID,
};
use crate::error::annotate;

const ENTRY_HEADER_LEN: usize = 60;

/// Representation of an archive entry header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    identifier: Vec<u8>,
    mtime: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
}

impl Header {
    /// Creates a header with the given file identifier and size, and all
    /// other fields set to zero.
    pub fn new(identifier: Vec<u8>, size: u64) -> Header {
        Header { identifier, mtime: 0, uid: 0, gid: 0, mode: 0, size }
    }

    /// Creates a header with the given file identifier and all other fields
    /// set from the given filesystem metadata.
    #[cfg(unix)]
    pub fn from_metadata(identifier: Vec<u8>, meta: &Metadata) -> Header {
        Header {
            identifier,
            mtime: meta.mtime() as u64,
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            size: meta.len(),
        }
    }

    #[cfg(not(unix))]
    pub fn from_metadata(identifier: Vec<u8>, meta: &Metadata) -> Header {
        Header::new(identifier, meta.len())
    }

    /// Returns the file identifier.
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// Sets the file identifier.
    pub fn set_identifier(&mut self, identifier: Vec<u8>) {
        self.identifier = identifier;
    }

    /// Returns the last modification time in Unix time format.
    pub fn mtime(&self) -> u64 {
        self.mtime
    }

    /// Sets the last modification time in Unix time format.
    pub fn set_mtime(&mut self, mtime: u64) {
        self.mtime = mtime;
    }

    /// Returns the value of the owner's user ID field.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Sets the value of the owner's user ID field.
    pub fn set_uid(&mut self, uid: u32) {
        self.uid = uid;
    }

    /// Returns the value of the group's user ID field.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the value of the group's user ID field.
    pub fn set_gid(&mut self, gid: u32) {
        self.gid = gid;
    }

    /// Returns the mode bits for this file.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Sets the mode bits for this file.
    pub fn set_mode(&mut self, mode: u32) {
        self.mode = mode;
    }

    /// Returns the length of the file, in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Sets the length of the file, in bytes.
    pub fn set_size(&mut self, size: u64) {
        self.size = size;
    }

    /// Parses and returns the next header and its length.  Returns `Ok(None)`
    /// if we are at EOF.
    pub(crate) fn read<R>(
        reader: &mut R,
        variant: &mut Variant,
        name_table: &mut Vec<u8>,
    ) -> Result<Option<(Header, u64)>>
    where
        R: Read,
    {
        let mut buffer = [0; 60];
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(None);
        } else if bytes_read < buffer.len() {
            if let Err(error) = reader.read_exact(&mut buffer[bytes_read..]) {
                if error.kind() == ErrorKind::UnexpectedEof {
                    let msg = "unexpected EOF in the middle of archive entry \
                               header";
                    return Err(Error::new(ErrorKind::UnexpectedEof, msg));
                } else {
                    let msg = "failed to read archive entry header";
                    return Err(annotate(error, msg));
                }
            }
        }
        let mut identifier = buffer[0..16].to_vec();
        while identifier.last() == Some(&b' ') {
            identifier.pop();
        }
        let mut size = parse_number("file size", &buffer[48..58], 10)?;
        let mut header_len = ENTRY_HEADER_LEN as u64;
        if *variant != Variant::BSD && identifier.starts_with(b"/") {
            *variant = Variant::GNU;
            if identifier == GNU_SYMBOL_LOOKUP_TABLE_ID {
                io::copy(&mut reader.by_ref().take(size), &mut io::sink())?;
                return Ok(Some((Header::new(identifier, size), header_len)));
            } else if identifier == GNU_NAME_TABLE_ID.as_bytes() {
                *name_table = vec![0; size as usize];
                reader.read_exact(name_table as &mut [u8]).map_err(|err| {
                    annotate(err, "failed to read name table")
                })?;
                return Ok(Some((Header::new(identifier, size), header_len)));
            }
            let start = parse_number("GNU filename index", &buffer[1..16], 10)?
                as usize;
            if start > name_table.len() {
                let msg = "GNU filename index out of range";
                return Err(Error::new(ErrorKind::InvalidData, msg));
            }
            let end = match name_table[start..]
                .iter()
                .position(|&ch| ch == b'/' || ch == b'\x00')
            {
                Some(len) => start + len,
                None => name_table.len(),
            };
            identifier = name_table[start..end].to_vec();
        } else if *variant != Variant::BSD && identifier.ends_with(b"/") {
            *variant = Variant::GNU;
            identifier.pop();
        }
        let mtime = parse_number_permitting_minus_one(
            "timestamp",
            &buffer[16..28],
            10,
        )?;
        let uid = if *variant == Variant::GNU {
            parse_number_permitting_empty("owner ID", &buffer[28..34], 10)?
        } else {
            parse_number("owner ID", &buffer[28..34], 10)?
        } as u32;
        let gid = if *variant == Variant::GNU {
            parse_number_permitting_empty("group ID", &buffer[34..40], 10)?
        } else {
            parse_number("group ID", &buffer[34..40], 10)?
        } as u32;
        let mode = parse_number("file mode", &buffer[40..48], 8)? as u32;
        if *variant != Variant::GNU && identifier.starts_with(b"#1/") {
            *variant = Variant::BSD;
            let padded_length =
                parse_number("BSD filename length", &buffer[3..16], 10)?;
            if size < padded_length {
                let msg = format!(
                    "Entry size ({}) smaller than extended \
                                   entry identifier length ({})",
                    size, padded_length
                );
                return Err(Error::new(ErrorKind::InvalidData, msg));
            }
            size -= padded_length;
            header_len += padded_length;
            let mut id_buffer = vec![0; padded_length as usize];
            let bytes_read = reader.read(&mut id_buffer)?;
            if bytes_read < id_buffer.len() {
                if let Err(error) =
                    reader.read_exact(&mut id_buffer[bytes_read..])
                {
                    if error.kind() == ErrorKind::UnexpectedEof {
                        let msg = "unexpected EOF in the middle of extended \
                                   entry identifier";
                        return Err(Error::new(ErrorKind::UnexpectedEof, msg));
                    } else {
                        let msg = "failed to read extended entry identifier";
                        return Err(annotate(error, msg));
                    }
                }
            }
            while id_buffer.last() == Some(&0) {
                id_buffer.pop();
            }
            identifier = id_buffer;
            if identifier == BSD_SYMBOL_LOOKUP_TABLE_ID
                || identifier == BSD_SORTED_SYMBOL_LOOKUP_TABLE_ID
            {
                io::copy(&mut reader.by_ref().take(size), &mut io::sink())?;
                return Ok(Some((Header::new(identifier, size), header_len)));
            }
        }
        Ok(Some((
            Header { identifier, mtime, uid, gid, mode, size },
            header_len,
        )))
    }

    pub(crate) fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.identifier.len() > 16 || self.identifier.contains(&b' ') {
            let padding_length = (4 - self.identifier.len() % 4) % 4;
            let padded_length = self.identifier.len() + padding_length;
            writeln!(
                writer,
                "#1/{:<13}{:<12}{:<6.6}{:<6.6}{:<8o}{:<10}`",
                padded_length,
                self.mtime,
                self.uid.to_string(),
                self.gid.to_string(),
                self.mode,
                self.size + padded_length as u64
            )?;
            writer.write_all(&self.identifier)?;
            writer.write_all(&vec![0; padding_length])?;
        } else {
            writer.write_all(&self.identifier)?;
            writer.write_all(&vec![b' '; 16 - self.identifier.len()])?;
            writeln!(
                writer,
                "{:<12}{:<6.6}{:<6.6}{:<8o}{:<10}`",
                self.mtime,
                self.uid.to_string(),
                self.gid.to_string(),
                self.mode,
                self.size
            )?;
        }
        Ok(())
    }

    pub(crate) fn write_gnu<W>(
        &self,
        writer: &mut W,
        names: &HashMap<Vec<u8>, usize>,
    ) -> Result<()>
    where
        W: Write,
    {
        if self.identifier.len() > 15 {
            let offset = names[&self.identifier];
            write!(writer, "/{:<15}", offset)?;
        } else {
            writer.write_all(&self.identifier)?;
            writer.write_all(b"/")?;
            writer.write_all(&vec![b' '; 15 - self.identifier.len()])?;
        }
        writeln!(
            writer,
            "{:<12}{:<6.6}{:<6.6}{:<8o}{:<10}`",
            self.mtime,
            self.uid.to_string(),
            self.gid.to_string(),
            self.mode,
            self.size
        )?;
        Ok(())
    }
}

fn parse_number(field_name: &str, bytes: &[u8], radix: u32) -> Result<u64> {
    if let Ok(string) = str::from_utf8(bytes) {
        if let Ok(value) = u64::from_str_radix(string.trim_end(), radix) {
            return Ok(value);
        }
    }
    let msg = format!(
        "Invalid {} field in entry header ({:?})",
        field_name,
        String::from_utf8_lossy(bytes)
    );
    Err(Error::new(ErrorKind::InvalidData, msg))
}

/*
 * Equivalent to parse_number() except for the case of "-1"
 * as MS tools may emit for mtime.
 */
fn parse_number_permitting_minus_one(
    field_name: &str,
    bytes: &[u8],
    radix: u32,
) -> Result<u64> {
    if let Ok(string) = str::from_utf8(bytes) {
        let trimmed = string.trim_end();
        if trimmed == "-1" {
            return Ok(0);
        } else if let Ok(value) = u64::from_str_radix(trimmed, radix) {
            return Ok(value);
        }
    }
    let msg = format!(
        "Invalid {} field in entry header ({:?})",
        field_name,
        String::from_utf8_lossy(bytes)
    );
    Err(Error::new(ErrorKind::InvalidData, msg))
}

/*
 * Equivalent to parse_number() except for the case of bytes being
 * all spaces (eg all 0x20) as MS tools emit for UID/GID
 */
fn parse_number_permitting_empty(
    field_name: &str,
    bytes: &[u8],
    radix: u32,
) -> Result<u64> {
    if let Ok(string) = str::from_utf8(bytes) {
        let trimmed = string.trim_end();
        if trimmed.is_empty() {
            return Ok(0);
        } else if let Ok(value) = u64::from_str_radix(trimmed, radix) {
            return Ok(value);
        }
    }
    let msg = format!(
        "Invalid {} field in entry header ({:?})",
        field_name,
        String::from_utf8_lossy(bytes)
    );
    Err(Error::new(ErrorKind::InvalidData, msg))
}
