//! A library for encoding/decoding Unix archive files.
//!
//! The API of this crate is meant to mirror that of the [`tar`
//! crate](https://crates.io/crates/tar).

#![warn(missing_docs)]

use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{self, Error, ErrorKind, Read, Result, Write};
use std::path::Path;

#[cfg(unix)] use std::os::unix::fs::MetadataExt;

// ========================================================================= //

const GLOBAL_HEADER: &'static str = "!<arch>\n";

// ========================================================================= //

/// Representation an archive entry header.
pub struct Header {
    identifier: String,
    mtime: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
}

impl Header {
    /// Creates a header with the given file identifier and size, and all
    /// other fields set to zero.
    pub fn new(identifier: String, size: u64) -> Header {
        Header {
            identifier: identifier,
            mtime: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            size: size,
        }
    }

    /// Creates a header with the given file identifier and all other fields
    /// set from the given filesystem metadata.
    #[cfg(unix)]
    pub fn from_metadata(identifier: String, meta: &Metadata) -> Header {
        Header {
            identifier: identifier,
            mtime: meta.mtime() as u64,
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            size: meta.len(),
        }
    }

    #[cfg(not(unix))]
    pub fn from_metadata(identifier: String, meta: &Metadata) -> Header {
        Header::new(identifier, meta.len())
    }

    /// Returns the file identifier.
    pub fn identifier(&self) -> &str { &self.identifier }

    /// Returns the last modification time in Unix time format.
    pub fn mtime(&self) -> u64 { self.mtime }

    /// Returns the value of the owner's user ID field.
    pub fn uid(&self) -> u32 { self.uid }

    /// Returns the value of the groups's user ID field.
    pub fn gid(&self) -> u32 { self.gid }

    /// Returns the mode bits for this file.
    pub fn mode(&self) -> u32 { self.mode }

    /// Returns the length of the file, in bytes.
    pub fn size(&self) -> u64 { self.size }

    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        write!(writer, "{:<15} {:<11} {:<5} {:<5} {:<7o} {:<10}`\n",
               self.identifier, self.mtime, self.uid, self.gid, self.mode,
               self.size)
    }
}

// ========================================================================= //

/// A structure for building archives.
///
/// This structure has methods for building up an archive from scratch into any
/// arbitrary writer.
pub struct Builder<W: Write> {
    writer: W,
    started: bool,
}

impl <W: Write> Builder<W> {
    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.
    pub fn new(writer: W) -> Builder<W> {
        Builder { writer: writer, started: false }
    }

    /// Unwrap this archive builder, returning the underlying writer object.
    pub fn into_inner(self) -> Result<W> { Ok(self.writer) }

    /// Adds a new entry to this archive.
    pub fn append<R: Read>(&mut self, header: &Header, mut data: R)
                           -> Result<()> {
        if !self.started {
            try!(self.writer.write_all(GLOBAL_HEADER.as_bytes()));
            self.started = true;
        }
        try!(header.write(&mut self.writer));
        let actual_size = try!(io::copy(&mut data, &mut self.writer));
        if actual_size != header.size() {
            let msg = format!("Wrong file size (header.size() = {}, actual \
                               size was {})", header.size(), actual_size);
            return Err(Error::new(ErrorKind::InvalidData, msg));
        }
        if actual_size % 2 != 0 {
            try!(self.writer.write_all(&['\n' as u8]));
        }
        Ok(())
    }

    /// Adds a file on the local filesystem to this archive, using the file
    /// name as its identifier.
    pub fn append_path<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let name: &OsStr = try!(path.as_ref().file_name().ok_or_else(|| {
            let msg = "Given path doesn't have a file name";
            Error::new(ErrorKind::InvalidInput, msg)
        }));
        let name: &str = try!(name.to_str().ok_or_else(|| {
            let msg = "Given path has a non-UTF8 file name";
            Error::new(ErrorKind::InvalidData, msg)
        }));
        self.append_file(name, &mut try!(File::open(&path)))
    }

    /// Adds a file to this archive, with the given name as its identifier.
    pub fn append_file(&mut self, name: &str, file: &mut File) -> Result<()> {
        let metadata = try!(file.metadata());
        let header = Header::from_metadata(name.to_string(), &metadata);
        self.append(&header, file)
    }
}

// ========================================================================= //

#[cfg(test)]
mod tests {
    use std::str;
    use super::{Builder, Header};

    #[test]
    fn build_archive_with_two_files() {
        let mut builder = Builder::new(Vec::new());
        let header1 = Header::new("foo.txt".to_string(), 7);
        builder.append(&header1, "foobar\n".as_bytes()).unwrap();
        let header2 = Header::new("baz.txt".to_string(), 4);
        builder.append(&header2, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap();
        let expected = "\
        !<arch>\n\
        foo.txt         0           0     0     0       7         `\n\
        foobar\n\n\
        baz.txt         0           0     0     0       4         `\n\
        baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }
}

// ========================================================================= //
