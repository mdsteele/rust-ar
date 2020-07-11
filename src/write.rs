use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Error, ErrorKind, Read, Result, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use super::*;

// ========================================================================= //

impl Header {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.identifier.len() > 16 || self.identifier.contains(&b' ') {
            let padding_length = (4 - self.identifier.len() % 4) % 4;
            let padded_length = self.identifier.len() + padding_length;
            write!(
                writer,
                "#1/{:<13}{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                padded_length,
                self.mtime,
                self.uid,
                self.gid,
                self.mode,
                self.size + padded_length as u64
            )?;
            writer.write_all(&self.identifier)?;
            writer.write_all(&vec![0; padding_length])?;
        } else {
            writer.write_all(&self.identifier)?;
            writer.write_all(&vec![b' '; 16 - self.identifier.len()])?;
            write!(
                writer,
                "{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                self.mtime, self.uid, self.gid, self.mode, self.size
            )?;
        }
        Ok(())
    }

    fn write_gnu<W>(
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
        write!(
            writer,
            "{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
            self.mtime, self.uid, self.gid, self.mode, self.size
        )?;
        Ok(())
    }
}
// ========================================================================= //

/// A structure for building Common or BSD-variant archives (the archive format
/// typically used on e.g. BSD and Mac OS X systems).
///
/// This structure has methods for building up an archive from scratch into any
/// arbitrary writer.
pub struct Builder<W: Write> {
    writer: W,
    started: bool,
}

impl<W: Write> Builder<W> {
    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.
    pub fn new(writer: W) -> Builder<W> {
        Builder {
            writer,
            started: false,
        }
    }

    /// Unwrap this archive builder, returning the underlying writer object.
    pub fn into_inner(self) -> Result<W> { Ok(self.writer) }

    /// Adds a new entry to this archive.
    pub fn append<R: Read>(
        &mut self,
        header: &Header,
        mut data: R,
    ) -> Result<()> {
        if !self.started {
            self.writer.write_all(GLOBAL_HEADER)?;
            self.started = true;
        }
        header.write(&mut self.writer)?;
        let actual_size = io::copy(&mut data, &mut self.writer)?;
        if actual_size != header.size() {
            let msg = format!(
                "Wrong file size (header.size() = {}, actual \
                               size was {})",
                header.size(),
                actual_size
            );
            return Err(Error::new(ErrorKind::InvalidData, msg));
        }
        if actual_size % 2 != 0 {
            self.writer.write_all(&['\n' as u8])?;
        }
        Ok(())
    }

    /// Adds a file on the local filesystem to this archive, using the file
    /// name as its identifier.
    pub fn append_path<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let name: &OsStr = path.as_ref().file_name().ok_or_else(|| {
            let msg = "Given path doesn't have a file name";
            Error::new(ErrorKind::InvalidInput, msg)
        })?;
        let identifier = osstr_to_bytes(name)?;
        let mut file = File::open(&path)?;
        self.append_file_id(identifier, &mut file)
    }

    /// Adds a file to this archive, with the given name as its identifier.
    pub fn append_file(&mut self, name: &[u8], file: &mut File) -> Result<()> {
        self.append_file_id(name.to_vec(), file)
    }

    fn append_file_id(&mut self, id: Vec<u8>, file: &mut File) -> Result<()> {
        let metadata = file.metadata()?;
        let header = Header::from_metadata(id, &metadata);
        self.append(&header, file)
    }
}

// ========================================================================= //

/// A structure for building GNU-variant archives (the archive format typically
/// used on e.g. GNU/Linux and Windows systems).
///
/// This structure has methods for building up an archive from scratch into any
/// arbitrary writer.
pub struct GnuBuilder<W: Write> {
    writer: W,
    short_names: HashSet<Vec<u8>>,
    long_names: HashMap<Vec<u8>, usize>,
    name_table_size: usize,
    name_table_needs_padding: bool,
    started: bool,
}

impl<W: Write> GnuBuilder<W> {
    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.  The `identifiers` parameter must give
    /// the complete list of entry identifiers that will be included in this
    /// archive.
    pub fn new(writer: W, identifiers: Vec<Vec<u8>>) -> GnuBuilder<W> {
        let mut short_names = HashSet::<Vec<u8>>::new();
        let mut long_names = HashMap::<Vec<u8>, usize>::new();
        let mut name_table_size: usize = 0;
        for identifier in identifiers.into_iter() {
            let length = identifier.len();
            if length > 15 {
                long_names.insert(identifier, name_table_size);
                name_table_size += length + 2;
            } else {
                short_names.insert(identifier);
            }
        }
        let name_table_needs_padding = name_table_size % 2 != 0;
        if name_table_needs_padding {
            name_table_size += 3; // ` /\n`
        }

        GnuBuilder {
            writer,
            short_names,
            long_names,
            name_table_size,
            name_table_needs_padding,
            started: false,
        }
    }

    /// Unwrap this archive builder, returning the underlying writer object.
    pub fn into_inner(self) -> Result<W> { Ok(self.writer) }

    /// Adds a new entry to this archive.
    pub fn append<R: Read>(
        &mut self,
        header: &Header,
        mut data: R,
    ) -> Result<()> {
        let is_long_name = header.identifier().len() > 15;
        let has_name = if is_long_name {
            self.long_names.contains_key(header.identifier())
        } else {
            self.short_names.contains(header.identifier())
        };
        if !has_name {
            let msg = format!(
                "Identifier {:?} was not in the list of \
                 identifiers passed to GnuBuilder::new()",
                String::from_utf8_lossy(header.identifier())
            );
            return Err(Error::new(ErrorKind::InvalidInput, msg));
        }

        if !self.started {
            self.writer.write_all(GLOBAL_HEADER)?;
            if !self.long_names.is_empty() {
                write!(
                    self.writer,
                    "{:<48}{:<10}`\n",
                    GNU_NAME_TABLE_ID, self.name_table_size
                )?;
                let mut entries: Vec<(usize, &[u8])> = self
                    .long_names
                    .iter()
                    .map(|(id, &start)| (start, id.as_slice()))
                    .collect();
                entries.sort();
                for (_, id) in entries {
                    self.writer.write_all(id)?;
                    self.writer.write_all(b"/\n")?;
                }
                if self.name_table_needs_padding {
                    self.writer.write_all(b" /\n")?;
                }
            }
            self.started = true;
        }

        header.write_gnu(&mut self.writer, &self.long_names)?;
        let actual_size = io::copy(&mut data, &mut self.writer)?;
        if actual_size != header.size() {
            let msg = format!(
                "Wrong file size (header.size() = {}, actual \
                               size was {})",
                header.size(),
                actual_size
            );
            return Err(Error::new(ErrorKind::InvalidData, msg));
        }
        if actual_size % 2 != 0 {
            self.writer.write_all(&['\n' as u8])?;
        }

        Ok(())
    }

    /// Adds a file on the local filesystem to this archive, using the file
    /// name as its identifier.
    pub fn append_path<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let name: &OsStr = path.as_ref().file_name().ok_or_else(|| {
            let msg = "Given path doesn't have a file name";
            Error::new(ErrorKind::InvalidInput, msg)
        })?;
        let identifier = osstr_to_bytes(name)?;
        let mut file = File::open(&path)?;
        self.append_file_id(identifier, &mut file)
    }

    /// Adds a file to this archive, with the given name as its identifier.
    pub fn append_file(&mut self, name: &[u8], file: &mut File) -> Result<()> {
        self.append_file_id(name.to_vec(), file)
    }

    fn append_file_id(&mut self, id: Vec<u8>, file: &mut File) -> Result<()> {
        let metadata = file.metadata()?;
        let header = Header::from_metadata(id, &metadata);
        self.append(&header, file)
    }
}

// ========================================================================= //

#[cfg(unix)]
fn osstr_to_bytes(string: &OsStr) -> Result<Vec<u8>> {
    Ok(string.as_bytes().to_vec())
}

#[cfg(windows)]
fn osstr_to_bytes(string: &OsStr) -> Result<Vec<u8>> {
    let mut bytes = Vec::<u8>::new();
    for wide in string.encode_wide() {
        // Little-endian:
        bytes.push((wide & 0xff) as u8);
        bytes.push((wide >> 8) as u8);
    }
    Ok(bytes)
}

#[cfg(not(any(unix, windows)))]
fn osstr_to_bytes(string: &OsStr) -> Result<Vec<u8>> {
    let utf8: &str = string.to_str().ok_or_else(|| {
        Error::new(ErrorKind::InvalidData, "Non-UTF8 file name")
    })?;
    Ok(utf8.as_bytes().to_vec())
}

// ========================================================================= //

#[cfg(test)]
mod tests {
    use super::{Archive, Builder, GnuBuilder, Header, Variant};
    use std::io::{Cursor, Read, Result, Seek, SeekFrom};
    use std::str;

    struct SlowReader<'a> {
        current_position: usize,
        buffer: &'a [u8],
    }

    impl<'a> Read for SlowReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if self.current_position >= self.buffer.len() {
                return Ok(0);
            }
            buf[0] = self.buffer[self.current_position];
            self.current_position += 1;
            return Ok(1);
        }
    }

    #[test]
    fn build_common_archive() {
        let mut builder = Builder::new(Vec::new());
        let mut header1 = Header::new(b"foo.txt".to_vec(), 7);
        header1.set_mtime(1487552916);
        header1.set_uid(501);
        header1.set_gid(20);
        header1.set_mode(0o100644);
        builder.append(&header1, "foobar\n".as_bytes()).unwrap();
        let header2 = Header::new(b"baz.txt".to_vec(), 4);
        builder.append(&header2, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap();
        let expected = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        baz.txt         0           0     0     0       4         `\n\
        baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_bsd_archive_with_long_filenames() {
        let mut builder = Builder::new(Vec::new());
        let mut header1 = Header::new(b"short".to_vec(), 1);
        header1.set_identifier(b"this_is_a_very_long_filename.txt".to_vec());
        header1.set_mtime(1487552916);
        header1.set_uid(501);
        header1.set_gid(20);
        header1.set_mode(0o100644);
        header1.set_size(7);
        builder.append(&header1, "foobar\n".as_bytes()).unwrap();
        let header2 = Header::new(
            b"and_this_is_another_very_long_filename.txt".to_vec(),
            4,
        );
        builder.append(&header2, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap();
        let expected = "\
        !<arch>\n\
        #1/32           1487552916  501   20    100644  39        `\n\
        this_is_a_very_long_filename.txtfoobar\n\n\
        #1/44           0           0     0     0       48        `\n\
        and_this_is_another_very_long_filename.txt\x00\x00baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_bsd_archive_with_space_in_filename() {
        let mut builder = Builder::new(Vec::new());
        let header = Header::new(b"foo bar".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap();
        let expected = "\
        !<arch>\n\
        #1/8            0           0     0     0       12        `\n\
        foo bar\x00baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_gnu_archive() {
        let names = vec![b"baz.txt".to_vec(), b"foo.txt".to_vec()];
        let mut builder = GnuBuilder::new(Vec::new(), names);
        let mut header1 = Header::new(b"foo.txt".to_vec(), 7);
        header1.set_mtime(1487552916);
        header1.set_uid(501);
        header1.set_gid(20);
        header1.set_mode(0o100644);
        builder.append(&header1, "foobar\n".as_bytes()).unwrap();
        let header2 = Header::new(b"baz.txt".to_vec(), 4);
        builder.append(&header2, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap();
        let expected = "\
        !<arch>\n\
        foo.txt/        1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        baz.txt/        0           0     0     0       4         `\n\
        baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_gnu_archive_with_long_filenames() {
        let names = vec![
            b"this_is_a_very_long_filename.txt".to_vec(),
            b"and_this_is_another_very_long_filename.txt".to_vec(),
        ];
        let mut builder = GnuBuilder::new(Vec::new(), names);
        let mut header1 = Header::new(b"short".to_vec(), 1);
        header1.set_identifier(b"this_is_a_very_long_filename.txt".to_vec());
        header1.set_mtime(1487552916);
        header1.set_uid(501);
        header1.set_gid(20);
        header1.set_mode(0o100644);
        header1.set_size(7);
        builder.append(&header1, "foobar\n".as_bytes()).unwrap();
        let header2 = Header::new(
            b"and_this_is_another_very_long_filename.txt".to_vec(),
            4,
        );
        builder.append(&header2, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap();
        let expected = "\
        !<arch>\n\
        //                                              78        `\n\
        this_is_a_very_long_filename.txt/\n\
        and_this_is_another_very_long_filename.txt/\n\
        /0              1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        /34             0           0     0     0       4         `\n\
        baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_gnu_archive_with_space_in_filename() {
        let names = vec![b"foo bar".to_vec()];
        let mut builder = GnuBuilder::new(Vec::new(), names);
        let header = Header::new(b"foo bar".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap();
        let expected = "\
        !<arch>\n\
        foo bar/        0           0     0     0       4         `\n\
        baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    #[should_panic(
        expected = "Identifier \\\"bar\\\" was not in the list of \
                               identifiers passed to GnuBuilder::new()"
    )]
    fn build_gnu_archive_with_unexpected_identifier() {
        let names = vec![b"foo".to_vec()];
        let mut builder = GnuBuilder::new(Vec::new(), names);
        let header = Header::new(b"bar".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes()).unwrap();
    }

    #[test]
    fn non_multiple_of_two_long_ident_in_gnu_archive() {
        let mut buffer = std::io::Cursor::new(Vec::new());

        {
            let filenames = vec![
                b"rust.metadata.bin".to_vec(),
                b"compiler_builtins-78891cf83a7d3547.dummy_name.rcgu.o"
                    .to_vec(),
            ];
            let mut builder = GnuBuilder::new(&mut buffer, filenames.clone());

            for filename in filenames {
                builder
                    .append(&Header::new(filename, 1), &mut (&[b'?'] as &[u8]))
                    .expect("add file");
            }
        }

        buffer.set_position(0);

        let mut archive = Archive::new(buffer);
        while let Some(entry) = archive.next_entry() {
            entry.unwrap();
        }
    }
}

// ========================================================================= //
