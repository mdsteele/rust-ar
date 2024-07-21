use std::io::{
    self, BufRead, BufReader, Error, ErrorKind, Read, Result, Seek, SeekFrom,
};

use crate::entry::Entry;
use crate::error::annotate;
use crate::header::Header;
use crate::symbols::Symbols;

pub(crate) const GLOBAL_HEADER_LEN: usize = 8;
pub(crate) const GLOBAL_HEADER: &[u8; GLOBAL_HEADER_LEN] = b"!<arch>\n";

pub(crate) const BSD_SYMBOL_LOOKUP_TABLE_ID: &[u8] = b"__.SYMDEF";
pub(crate) const BSD_SORTED_SYMBOL_LOOKUP_TABLE_ID: &[u8] =
    b"__.SYMDEF SORTED";

pub(crate) const GNU_NAME_TABLE_ID: &str = "//";
pub(crate) const GNU_SYMBOL_LOOKUP_TABLE_ID: &[u8] = b"/";

/// Variants of the Unix archive format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Variant {
    /// Used by Debian package files; allows only short filenames.
    Common,
    /// Used by BSD `ar` (and OS X); backwards-compatible with common variant.
    BSD,
    /// Used by GNU `ar` (and Windows); incompatible with common variant.
    GNU,
}

pub(crate) struct HeaderAndLocation {
    header: Header,
    header_start: u64,
    data_start: u64,
}

/// A structure for reading archives.
pub struct Archive<R: Read> {
    reader: R,
    variant: Variant,
    name_table: Vec<u8>,
    entry_headers: Vec<HeaderAndLocation>,
    new_entry_start: u64,
    next_entry_index: usize,
    pub(crate) symbol_table_header: Option<HeaderAndLocation>,
    pub(crate) symbol_table: Option<Vec<(Vec<u8>, u64)>>,
    started: bool, // True if we've read past the global header.
    padding: bool, // True if there's a padding byte before the next entry.
    scanned: bool, // True if entry_headers is complete.
    error: bool,   // True if we have encountered an error.
}

impl<R: Read> Archive<R> {
    /// Create a new archive reader with the underlying reader object as the
    /// source of all data read.
    pub fn new(reader: R) -> Archive<R> {
        Archive {
            reader,
            variant: Variant::Common,
            name_table: Vec::new(),
            entry_headers: Vec::new(),
            new_entry_start: GLOBAL_HEADER_LEN as u64,
            next_entry_index: 0,
            symbol_table_header: None,
            symbol_table: None,
            started: false,
            padding: false,
            scanned: false,
            error: false,
        }
    }

    /// Returns which format variant this archive appears to be so far.
    ///
    /// Note that this may not be accurate before the archive has been fully
    /// read (i.e. before the `next_entry()` method returns `None`).  In
    /// particular, a new `Archive` object that hasn't yet read any data at all
    /// will always return `Variant::Common`.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// Unwrap this archive reader, returning the underlying reader object.
    pub fn into_inner(self) -> Result<R> {
        Ok(self.reader)
    }

    fn is_name_table_id(&self, identifier: &[u8]) -> bool {
        self.variant == Variant::GNU
            && identifier == GNU_NAME_TABLE_ID.as_bytes()
    }

    fn is_symbol_lookup_table_id(&self, identifier: &[u8]) -> bool {
        match self.variant {
            Variant::Common => false,
            Variant::BSD => {
                identifier == BSD_SYMBOL_LOOKUP_TABLE_ID
                    || identifier == BSD_SORTED_SYMBOL_LOOKUP_TABLE_ID
            }
            Variant::GNU => identifier == GNU_SYMBOL_LOOKUP_TABLE_ID,
        }
    }

    fn read_global_header_if_necessary(&mut self) -> Result<()> {
        if self.started {
            return Ok(());
        }
        let mut buffer = [0; GLOBAL_HEADER_LEN];
        match self.reader.read_exact(&mut buffer) {
            Ok(()) => {}
            Err(error) => {
                self.error = true;
                return Err(annotate(error, "failed to read global header"));
            }
        }
        if &buffer != GLOBAL_HEADER {
            self.error = true;
            let msg = "Not an archive file (invalid global header)";
            return Err(Error::new(ErrorKind::InvalidData, msg));
        }
        self.started = true;
        Ok(())
    }

    /// Reads the next entry from the archive, or returns None if there are no
    /// more.
    pub fn next_entry(&mut self) -> Option<Result<Entry<R>>> {
        loop {
            if self.error {
                return None;
            }
            if self.scanned
                && self.next_entry_index == self.entry_headers.len()
            {
                return None;
            }
            match self.read_global_header_if_necessary() {
                Ok(()) => {}
                Err(error) => return Some(Err(error)),
            }
            if self.padding {
                let mut buffer = [0u8; 1];
                match self.reader.read_exact(&mut buffer) {
                    Ok(()) => {
                        if buffer[0] != b'\n' {
                            self.error = true;
                            let msg = format!(
                                "invalid padding byte ({})",
                                buffer[0]
                            );
                            let error =
                                Error::new(ErrorKind::InvalidData, msg);
                            return Some(Err(error));
                        }
                    }
                    Err(error) => {
                        if error.kind() != ErrorKind::UnexpectedEof {
                            self.error = true;
                            let msg = "failed to read padding byte";
                            return Some(Err(annotate(error, msg)));
                        }
                    }
                }
                self.padding = false;
            }
            let header_start = self.new_entry_start;
            match Header::read(
                &mut self.reader,
                &mut self.variant,
                &mut self.name_table,
            ) {
                Ok(Some((header, header_len))) => {
                    let size = header.size();
                    if size % 2 != 0 {
                        self.padding = true;
                    }
                    if self.next_entry_index == self.entry_headers.len() {
                        self.new_entry_start += header_len + size + (size % 2);
                    }
                    if self.is_name_table_id(header.identifier()) {
                        continue;
                    }
                    if self.is_symbol_lookup_table_id(header.identifier()) {
                        self.symbol_table_header = Some(HeaderAndLocation {
                            header,
                            header_start,
                            data_start: header_start + header_len,
                        });
                        continue;
                    }
                    if self.next_entry_index == self.entry_headers.len() {
                        self.entry_headers.push(HeaderAndLocation {
                            header,
                            header_start,
                            data_start: header_start + header_len,
                        });
                    }
                    let header =
                        &self.entry_headers[self.next_entry_index].header;
                    self.next_entry_index += 1;
                    return Some(Ok(Entry {
                        header,
                        reader: self.reader.by_ref(),
                        length: size,
                        position: 0,
                    }));
                }
                Ok(None) => {
                    self.scanned = true;
                    return None;
                }
                Err(error) => {
                    self.error = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

impl<R: Read + Seek> Archive<R> {
    fn scan_if_necessary(&mut self) -> io::Result<()> {
        if self.scanned {
            return Ok(());
        }
        self.read_global_header_if_necessary()?;
        loop {
            let header_start = self.new_entry_start;
            self.reader.seek(SeekFrom::Start(header_start))?;
            if let Some((header, header_len)) = Header::read(
                &mut self.reader,
                &mut self.variant,
                &mut self.name_table,
            )? {
                let size = header.size();
                self.new_entry_start += header_len + size + (size % 2);
                if self.is_name_table_id(header.identifier()) {
                    continue;
                }
                if self.is_symbol_lookup_table_id(header.identifier()) {
                    self.symbol_table_header = Some(HeaderAndLocation {
                        header,
                        header_start,
                        data_start: header_start + header_len,
                    });
                    continue;
                }
                self.entry_headers.push(HeaderAndLocation {
                    header,
                    header_start,
                    data_start: header_start + header_len,
                });
            } else {
                break;
            }
        }
        // Resume our previous position in the file.
        if self.next_entry_index < self.entry_headers.len() {
            let offset =
                self.entry_headers[self.next_entry_index].header_start;
            self.reader.seek(SeekFrom::Start(offset))?;
        }
        self.scanned = true;
        Ok(())
    }

    /// Scans the archive and returns the total number of entries in the
    /// archive (not counting special entries, such as the GNU archive name
    /// table or symbol table, that are not returned by `next_entry()`).
    pub fn count_entries(&mut self) -> io::Result<usize> {
        self.scan_if_necessary()?;
        Ok(self.entry_headers.len())
    }

    /// Scans the archive and jumps to the entry at the given index.  Returns
    /// an error if the index is not less than the result of `count_entries()`.
    pub fn jump_to_entry(&mut self, index: usize) -> io::Result<Entry<R>> {
        self.scan_if_necessary()?;
        if index >= self.entry_headers.len() {
            let msg = "Entry index out of bounds";
            return Err(Error::new(ErrorKind::InvalidInput, msg));
        }
        let offset = self.entry_headers[index].data_start;
        self.reader.seek(SeekFrom::Start(offset))?;
        let header = &self.entry_headers[index].header;
        let size = header.size();
        self.padding = size % 2 != 0;
        self.next_entry_index = index + 1;
        Ok(Entry {
            header,
            reader: self.reader.by_ref(),
            length: size,
            position: 0,
        })
    }

    fn parse_symbol_table_if_necessary(&mut self) -> io::Result<()> {
        self.scan_if_necessary()?;
        if self.symbol_table.is_some() {
            return Ok(());
        }
        if let Some(ref header_and_loc) = self.symbol_table_header {
            let offset = header_and_loc.data_start;
            self.reader.seek(SeekFrom::Start(offset))?;
            let mut reader = BufReader::new(
                self.reader.by_ref().take(header_and_loc.header.size()),
            );
            if self.variant == Variant::GNU {
                let num_symbols = read_be_u32(&mut reader)? as usize;
                let mut symbol_offsets =
                    Vec::<u32>::with_capacity(num_symbols);
                for _ in 0..num_symbols {
                    let offset = read_be_u32(&mut reader)?;
                    symbol_offsets.push(offset);
                }
                let mut symbol_table = Vec::with_capacity(num_symbols);
                for offset in symbol_offsets.into_iter() {
                    let mut buffer = Vec::<u8>::new();
                    reader.read_until(0, &mut buffer)?;
                    if buffer.last() == Some(&0) {
                        buffer.pop();
                    }
                    buffer.shrink_to_fit();
                    symbol_table.push((buffer, offset as u64));
                }
                self.symbol_table = Some(symbol_table);
            } else {
                let num_symbols = (read_le_u32(&mut reader)? / 8) as usize;
                let mut symbol_offsets =
                    Vec::<(u32, u32)>::with_capacity(num_symbols);
                for _ in 0..num_symbols {
                    let str_offset = read_le_u32(&mut reader)?;
                    let file_offset = read_le_u32(&mut reader)?;
                    symbol_offsets.push((str_offset, file_offset));
                }
                let str_table_len = read_le_u32(&mut reader)?;
                let mut str_table_data = vec![0u8; str_table_len as usize];
                reader.read_exact(&mut str_table_data).map_err(|err| {
                    annotate(err, "failed to read string table")
                })?;
                let mut symbol_table = Vec::with_capacity(num_symbols);
                for (str_start, file_offset) in symbol_offsets.into_iter() {
                    let str_start = str_start as usize;
                    let mut str_end = str_start;
                    while str_end < str_table_data.len()
                        && str_table_data[str_end] != 0u8
                    {
                        str_end += 1;
                    }
                    let string = &str_table_data[str_start..str_end];
                    symbol_table.push((string.to_vec(), file_offset as u64));
                }
                self.symbol_table = Some(symbol_table);
            }
        }
        // Resume our previous position in the file.
        if !self.entry_headers.is_empty() {
            let offset =
                self.entry_headers[self.next_entry_index].header_start;
            self.reader.seek(SeekFrom::Start(offset))?;
        }
        Ok(())
    }

    /// Scans the archive and returns an iterator over the symbols in the
    /// archive's symbol table.  If the archive doesn't have a symbol table,
    /// this method will still succeed, but the iterator won't produce any
    /// values.
    pub fn symbols(&mut self) -> io::Result<Symbols<R>> {
        self.parse_symbol_table_if_necessary()?;
        Ok(Symbols { archive: self, index: 0 })
    }
}

fn read_le_u32(r: &mut impl io::Read) -> io::Result<u32> {
    let mut buf = [0; 4];
    r.read_exact(&mut buf).map(|()| u32::from_le_bytes(buf))
}

fn read_be_u32(r: &mut impl io::Read) -> io::Result<u32> {
    let mut buf = [0; 4];
    r.read_exact(&mut buf).map(|()| u32::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use crate::{Archive, GnuBuilder, Header, Variant};
    use std::io::{Cursor, Read, Result, Seek, SeekFrom};

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
    fn read_common_archive() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.awesome.txt 1487552919  501   20    100644  22        `\n\
        This file is awesome!\n\
        baz.txt         1487552349  42    12345 100664  4         `\n\
        baz\n";
        let reader =
            SlowReader { current_position: 0, buffer: input.as_bytes() };
        let mut archive = Archive::new(reader);
        {
            // Parse the first entry and check the header values.
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), b"foo.txt");
            assert_eq!(entry.header().mtime(), 1487552916);
            assert_eq!(entry.header().uid(), 501);
            assert_eq!(entry.header().gid(), 20);
            assert_eq!(entry.header().mode(), 0o100644);
            assert_eq!(entry.header().size(), 7);
            // Read the first few bytes of the entry data and make sure they're
            // correct.
            let mut buffer = [0; 4];
            entry.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, "foob".as_bytes());
            // Dropping the Entry object should automatically consume the rest
            // of the entry data so that the archive reader is ready to parse
            // the next entry.
        }
        {
            // Parse the second entry and check a couple header values.
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), b"bar.awesome.txt");
            assert_eq!(entry.header().size(), 22);
            // Read in all the entry data.
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "This file is awesome!\n".as_bytes());
        }
        {
            // Parse the third entry and check a couple header values.
            let entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), b"baz.txt");
            assert_eq!(entry.header().size(), 4);
        }
        assert!(archive.next_entry().is_none());
        assert_eq!(archive.variant(), Variant::Common);
    }

    #[test]
    fn read_bsd_archive_with_long_filenames() {
        let input = "\
        !<arch>\n\
        #1/32           1487552916  501   20    100644  39        `\n\
        this_is_a_very_long_filename.txtfoobar\n\n\
        #1/44           0           0     0     0       48        `\n\
        and_this_is_another_very_long_filename.txt\x00\x00baz\n";
        let mut archive = Archive::new(input.as_bytes());
        {
            // Parse the first entry and check the header values.
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            assert_eq!(entry.header().mtime(), 1487552916);
            assert_eq!(entry.header().uid(), 501);
            assert_eq!(entry.header().gid(), 20);
            assert_eq!(entry.header().mode(), 0o100644);
            // We should get the size of the actual file, not including the
            // filename, even though this is not the value that's in the size
            // field in the input.
            assert_eq!(entry.header().size(), 7);
            // Read in the entry data; we should get only the payload and not
            // the filename.
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        {
            // Parse the second entry and check a couple header values.
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "and_this_is_another_very_long_filename.txt".as_bytes()
            );
            assert_eq!(entry.header().size(), 4);
            // Read in the entry data; we should get only the payload and not
            // the filename or the padding bytes.
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        assert!(archive.next_entry().is_none());
        assert_eq!(archive.variant(), Variant::BSD);
    }

    #[test]
    fn read_bsd_archive_with_space_in_filename() {
        let input = "\
        !<arch>\n\
        #1/8            0           0     0     0       12        `\n\
        foo bar\x00baz\n";
        let mut archive = Archive::new(input.as_bytes());
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "foo bar".as_bytes());
            assert_eq!(entry.header().size(), 4);
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        assert!(archive.next_entry().is_none());
        assert_eq!(archive.variant(), Variant::BSD);
    }

    #[test]
    fn read_gnu_archive() {
        let input = "\
        !<arch>\n\
        foo.txt/        1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.awesome.txt/1487552919  501   20    100644  22        `\n\
        This file is awesome!\n\
        baz.txt/        1487552349  42    12345 100664  4         `\n\
        baz\n";
        let mut archive = Archive::new(input.as_bytes());
        {
            let entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "foo.txt".as_bytes());
            assert_eq!(entry.header().size(), 7);
        }
        {
            let entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "bar.awesome.txt".as_bytes()
            );
            assert_eq!(entry.header().size(), 22);
        }
        {
            let entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "baz.txt".as_bytes());
            assert_eq!(entry.header().size(), 4);
        }
        assert!(archive.next_entry().is_none());
        assert_eq!(archive.variant(), Variant::GNU);
    }

    #[test]
    fn read_gnu_archive_with_long_filenames() {
        let input = "\
        !<arch>\n\
        //                                              78        `\n\
        this_is_a_very_long_filename.txt/\n\
        and_this_is_another_very_long_filename.txt/\n\
        /0              1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        /34             0           0     0     0       4         `\n\
        baz\n";
        let mut archive = Archive::new(input.as_bytes());
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            assert_eq!(entry.header().mtime(), 1487552916);
            assert_eq!(entry.header().uid(), 501);
            assert_eq!(entry.header().gid(), 20);
            assert_eq!(entry.header().mode(), 0o100644);
            assert_eq!(entry.header().size(), 7);
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "and_this_is_another_very_long_filename.txt".as_bytes()
            );
            assert_eq!(entry.header().size(), 4);
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        assert!(archive.next_entry().is_none());
        assert_eq!(archive.variant(), Variant::GNU);
    }

    // MS `.lib` files are very similar to GNU `ar` archives, but with a few
    // tweaks:
    // * File names in the name table are terminated by null, rather than /\n
    // * Numeric entries may be all empty string, interpreted as 0, possibly?
    #[test]
    fn read_ms_archive_with_long_filenames() {
        let input = "\
        !<arch>\n\
        //                                              76        `\n\
        this_is_a_very_long_filename.txt\x00\
        and_this_is_another_very_long_filename.txt\x00\
        /0              1487552916              100644  7         `\n\
        foobar\n\n\
        /33             1446790218              100666  4         `\n\
        baz\n";
        let mut archive = Archive::new(input.as_bytes());
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            assert_eq!(entry.header().mtime(), 1487552916);
            assert_eq!(entry.header().uid(), 0);
            assert_eq!(entry.header().gid(), 0);
            assert_eq!(entry.header().mode(), 0o100644);
            assert_eq!(entry.header().size(), 7);
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "and_this_is_another_very_long_filename.txt".as_bytes()
            );
            assert_eq!(entry.header().size(), 4);
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        assert!(archive.next_entry().is_none());
        assert_eq!(archive.variant(), Variant::GNU);
    }

    #[test]
    fn read_gnu_archive_with_space_in_filename() {
        let input = "\
        !<arch>\n\
        foo bar/        0           0     0     0       4         `\n\
        baz\n";
        let mut archive = Archive::new(input.as_bytes());
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "foo bar".as_bytes());
            assert_eq!(entry.header().size(), 4);
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        assert!(archive.next_entry().is_none());
        assert_eq!(archive.variant(), Variant::GNU);
    }

    #[test]
    fn read_gnu_archive_with_symbol_lookup_table() {
        let input = b"\
        !<arch>\n\
        /               0           0     0     0       15        `\n\
        \x00\x00\x00\x01\x00\x00\x00\xb2foobar\x00\n\
        //                                              34        `\n\
        this_is_a_very_long_filename.txt/\n\
        /0              1487552916  501   20    100644  7         `\n\
        foobar\n";
        let mut archive = Archive::new(input as &[u8]);
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        assert!(archive.next_entry().is_none());
    }

    #[test]
    fn read_archive_with_no_padding_byte_in_final_entry() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        bar.txt         1487552919  501   20    100644  3         `\n\
        foo";
        let mut archive = Archive::new(input.as_bytes());
        {
            let entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "foo.txt".as_bytes());
            assert_eq!(entry.header().size(), 7);
        }
        {
            let entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "bar.txt".as_bytes());
            assert_eq!(entry.header().size(), 3);
        }
        assert!(archive.next_entry().is_none());
    }

    #[test]
    #[should_panic(expected = "Invalid timestamp field in entry header \
                               (\\\"helloworld  \\\")")]
    fn read_archive_with_invalid_mtime() {
        let input = "\
        !<arch>\n\
        foo.txt         helloworld  501   20    100644  7         `\n\
        foobar\n\n";
        let mut archive = Archive::new(input.as_bytes());
        archive.next_entry().unwrap().unwrap();
    }

    #[test]
    fn read_archive_with_mtime_minus_one() {
        let input = "\
        !<arch>\n\
        foo.txt         -1          501   20    100644  7         `\n\
        foobar\n\n";
        let mut archive = Archive::new(input.as_bytes());
        archive.next_entry().unwrap().unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid owner ID field in entry header \
                               (\\\"foo   \\\")")]
    fn read_archive_with_invalid_uid() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  foo   20    100644  7         `\n\
        foobar\n\n";
        let mut archive = Archive::new(input.as_bytes());
        archive.next_entry().unwrap().unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid group ID field in entry header \
                               (\\\"bar   \\\")")]
    fn read_archive_with_invalid_gid() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   bar   100644  7         `\n\
        foobar\n\n";
        let mut archive = Archive::new(input.as_bytes());
        archive.next_entry().unwrap().unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid file mode field in entry header \
                               (\\\"foobar  \\\")")]
    fn read_archive_with_invalid_mode() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    foobar  7         `\n\
        foobar\n\n";
        let mut archive = Archive::new(input.as_bytes());
        archive.next_entry().unwrap().unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid file size field in entry header \
                               (\\\"whatever  \\\")")]
    fn read_archive_with_invalid_size() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  whatever  `\n\
        foobar\n\n";
        let mut archive = Archive::new(input.as_bytes());
        archive.next_entry().unwrap().unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid BSD filename length field in entry \
                               header (\\\"foobar       \\\")")]
    fn read_bsd_archive_with_invalid_filename_length() {
        let input = "\
        !<arch>\n\
        #1/foobar       1487552916  501   20    100644  39        `\n\
        this_is_a_very_long_filename.txtfoobar\n\n";
        let mut archive = Archive::new(input.as_bytes());
        archive.next_entry().unwrap().unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid GNU filename index field in entry \
                               header (\\\"foobar         \\\")")]
    fn read_gnu_archive_with_invalid_filename_index() {
        let input = "\
        !<arch>\n\
        //                                              34        `\n\
        this_is_a_very_long_filename.txt/\n\
        /foobar         1487552916  501   20    100644  7         `\n\
        foobar\n\n";
        let mut archive = Archive::new(input.as_bytes());
        archive.next_entry().unwrap().unwrap();
    }

    #[test]
    fn seek_within_entry() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  31        `\n\
        abcdefghij0123456789ABCDEFGHIJ\n\n\
        bar.awesome.txt 1487552919  501   20    100644  22        `\n\
        This file is awesome!\n";
        let mut archive = Archive::new(Cursor::new(input.as_bytes()));
        {
            // Parse the first entry, then seek around the entry, performing
            // different reads.
            let mut entry = archive.next_entry().unwrap().unwrap();
            let mut buffer = [0; 5];
            entry.seek(SeekFrom::Start(10)).unwrap();
            entry.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, "01234".as_bytes());
            entry.seek(SeekFrom::Start(5)).unwrap();
            entry.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, "fghij".as_bytes());
            entry.seek(SeekFrom::End(-10)).unwrap();
            entry.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, "BCDEF".as_bytes());
            entry.seek(SeekFrom::End(-30)).unwrap();
            entry.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, "bcdef".as_bytes());
            entry.seek(SeekFrom::Current(10)).unwrap();
            entry.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, "6789A".as_bytes());
            entry.seek(SeekFrom::Current(-8)).unwrap();
            entry.read_exact(&mut buffer).unwrap();
            assert_eq!(&buffer, "34567".as_bytes());
            // Dropping the Entry object should automatically consume the rest
            // of the entry data so that the archive reader is ready to parse
            // the next entry.
        }
        {
            // Parse the second entry and read in all the entry data.
            let mut entry = archive.next_entry().unwrap().unwrap();
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "This file is awesome!\n".as_bytes());
        }
    }

    #[test]
    #[should_panic(expected = "Invalid seek to negative position (-17)")]
    fn seek_entry_to_negative_position() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  30        `\n\
        abcdefghij0123456789ABCDEFGHIJ";
        let mut archive = Archive::new(Cursor::new(input.as_bytes()));
        let mut entry = archive.next_entry().unwrap().unwrap();
        entry.seek(SeekFrom::End(-47)).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid seek to position past end of entry \
                               (47 vs. 30)")]
    fn seek_entry_beyond_end() {
        let input = "\
        !<arch>\n\
        foo.txt         1487552916  501   20    100644  30        `\n\
        abcdefghij0123456789ABCDEFGHIJ";
        let mut archive = Archive::new(Cursor::new(input.as_bytes()));
        let mut entry = archive.next_entry().unwrap().unwrap();
        entry.seek(SeekFrom::Start(47)).unwrap();
    }

    #[test]
    fn count_entries_in_bsd_archive() {
        let input = b"\
        !<arch>\n\
        #1/32           1487552916  501   20    100644  39        `\n\
        this_is_a_very_long_filename.txtfoobar\n\n\
        baz.txt         0           0     0     0       4         `\n\
        baz\n";
        let mut archive = Archive::new(Cursor::new(input as &[u8]));
        assert_eq!(archive.count_entries().unwrap(), 2);
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        assert_eq!(archive.count_entries().unwrap(), 2);
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "baz.txt".as_bytes());
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        assert_eq!(archive.count_entries().unwrap(), 2);
    }

    #[test]
    fn count_entries_in_gnu_archive() {
        let input = b"\
        !<arch>\n\
        /               0           0     0     0       15        `\n\
        \x00\x00\x00\x01\x00\x00\x00\xb2foobar\x00\n\
        //                                              34        `\n\
        this_is_a_very_long_filename.txt/\n\
        /0              1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        baz.txt/        1487552349  42    12345 100664  4         `\n\
        baz\n";
        let mut archive = Archive::new(Cursor::new(input as &[u8]));
        assert_eq!(archive.count_entries().unwrap(), 2);
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        assert_eq!(archive.count_entries().unwrap(), 2);
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "baz.txt".as_bytes());
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        assert_eq!(archive.count_entries().unwrap(), 2);
    }

    #[test]
    fn jump_to_entry_in_bsd_archive() {
        let input = b"\
        !<arch>\n\
        hello.txt       1487552316  42    12345 100644  14        `\n\
        Hello, world!\n\
        #1/32           1487552916  501   20    100644  39        `\n\
        this_is_a_very_long_filename.txtfoobar\n\n\
        baz.txt         1487552349  42    12345 100664  4         `\n\
        baz\n";
        let mut archive = Archive::new(Cursor::new(input as &[u8]));
        {
            // Jump to the second entry and check its contents.
            let mut entry = archive.jump_to_entry(1).unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        {
            // Read the next entry, which should be the third one now.
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "baz.txt".as_bytes());
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        // We should be at the end of the archive now.
        assert!(archive.next_entry().is_none());
        {
            // Jump back to the first entry and check its contents.
            let mut entry = archive.jump_to_entry(0).unwrap();
            assert_eq!(entry.header().identifier(), "hello.txt".as_bytes());
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "Hello, world!\n".as_bytes());
        }
        {
            // Read the next entry, which should be the second one again.
            let mut entry = archive.jump_to_entry(1).unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        {
            // Jump back to the first entry and check its contents.
            let mut entry = archive.jump_to_entry(0).unwrap();
            assert_eq!(entry.header().identifier(), "hello.txt".as_bytes());
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "Hello, world!\n".as_bytes());
        }
        {
            // Read the next entry, which should be the second one again.
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
    }

    #[test]
    fn jump_to_entry_in_gnu_archive() {
        let input = b"\
        !<arch>\n\
        //                                              34        `\n\
        this_is_a_very_long_filename.txt/\n\
        hello.txt/      1487552316  42    12345 100644  14        `\n\
        Hello, world!\n\
        /0              1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        baz.txt/        1487552349  42    12345 100664  4         `\n\
        baz\n";
        let mut archive = Archive::new(Cursor::new(input as &[u8]));
        {
            // Jump to the second entry and check its contents.
            let mut entry = archive.jump_to_entry(1).unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
        {
            // Read the next entry, which should be the third one now.
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "baz.txt".as_bytes());
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "baz\n".as_bytes());
        }
        // We should be at the end of the archive now.
        assert!(archive.next_entry().is_none());
        {
            // Jump back to the first entry and check its contents.
            let mut entry = archive.jump_to_entry(0).unwrap();
            assert_eq!(entry.header().identifier(), "hello.txt".as_bytes());
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "Hello, world!\n".as_bytes());
        }
        {
            // Read the next entry, which should be the second one again.
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(
                entry.header().identifier(),
                "this_is_a_very_long_filename.txt".as_bytes()
            );
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer).unwrap();
            assert_eq!(&buffer as &[u8], "foobar\n".as_bytes());
        }
    }

    #[test]
    fn list_symbols_in_bsd_archive() {
        let input = b"\
        !<arch>\n\
        #1/12           0           0     0     0       60        `\n\
        __.SYMDEF\x00\x00\x00\x18\x00\x00\x00\
        \x00\x00\x00\x00\x80\x00\x00\x00\
        \x07\x00\x00\x00\x80\x00\x00\x00\
        \x0b\x00\x00\x00\x80\x00\x00\x00\
        \x10\x00\x00\x00foobar\x00baz\x00quux\x00\
        foo.o/          1487552916  501   20    100644  16        `\n\
        foobar,baz,quux\n";
        let mut archive = Archive::new(Cursor::new(input as &[u8]));
        assert_eq!(archive.symbols().unwrap().len(), 3);
        assert_eq!(archive.variant(), Variant::BSD);
        let symbols = archive.symbols().unwrap().collect::<Vec<&[u8]>>();
        let expected: Vec<&[u8]> = vec![b"foobar", b"baz", b"quux"];
        assert_eq!(symbols, expected);
    }

    #[test]
    fn list_sorted_symbols_in_bsd_archive() {
        let input = b"\
        !<arch>\n\
        #1/16           0           0     0     0       64        `\n\
        __.SYMDEF SORTED\x18\x00\x00\x00\
        \x00\x00\x00\x00\x80\x00\x00\x00\
        \x04\x00\x00\x00\x80\x00\x00\x00\
        \x0b\x00\x00\x00\x80\x00\x00\x00\
        \x10\x00\x00\x00baz\x00foobar\x00quux\x00\
        foo.o/          1487552916  501   20    100644  16        `\n\
        foobar,baz,quux\n";
        let mut archive = Archive::new(Cursor::new(input as &[u8]));
        assert_eq!(archive.symbols().unwrap().len(), 3);
        assert_eq!(archive.variant(), Variant::BSD);
        let symbols = archive.symbols().unwrap().collect::<Vec<&[u8]>>();
        let expected: Vec<&[u8]> = vec![b"baz", b"foobar", b"quux"];
        assert_eq!(symbols, expected);
    }

    #[test]
    fn list_symbols_in_gnu_archive() {
        let input = b"\
        !<arch>\n\
        /               0           0     0     0       32        `\n\
        \x00\x00\x00\x03\x00\x00\x00\x5c\x00\x00\x00\x5c\x00\x00\x00\x5c\
        foobar\x00baz\x00quux\x00\
        foo.o/          1487552916  501   20    100644  16        `\n\
        foobar,baz,quux\n";
        let mut archive = Archive::new(Cursor::new(input as &[u8]));
        assert_eq!(archive.symbols().unwrap().len(), 3);
        assert_eq!(archive.variant(), Variant::GNU);
        let symbols = archive.symbols().unwrap().collect::<Vec<&[u8]>>();
        let expected: Vec<&[u8]> = vec![b"foobar", b"baz", b"quux"];
        assert_eq!(symbols, expected);
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

    /// Regression test for https://github.com/mdsteele/rust-ar/issues/22
    #[test]
    #[should_panic(expected = "GNU filename index out of range")]
    fn issue_22() {
        let data = &[
            33, 60, 97, 114, 99, 104, 62, 10, 99, 104, 60, 159, 149, 33, 62,
            10, 219, 87, 219, 219, 219, 96, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 47, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 49, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 39, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 51, 49, 50, 56, 48, 48, 54, 54, 54, 51, 52, 56,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 47, 48, 0, 40,
        ];
        let mut archive = Archive::new(std::io::Cursor::new(data));
        let _num_entries = archive.count_entries().unwrap();
    }

    /// Test for entries with octal literal (0o) prefix in the mode field.
    #[test]
    fn read_archive_with_radix_prefixed_mode() {
        let input = "\
        !<arch>\n\
        foo.txt/        1487552916  501   20    0o1006447         `\n\
        foobar\n";
        let mut archive = Archive::new(input.as_bytes());
        {
            let entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.header().identifier(), "foo.txt".as_bytes());
            assert_eq!(entry.header().mode(), 0o100644);
            assert_eq!(entry.header().size(), 7);
        }
        assert!(archive.next_entry().is_none());
    }
}
