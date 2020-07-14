use std::cmp;
use std::io::{
    self, BufRead, BufReader, Error, ErrorKind, Read, Result, Seek, SeekFrom,
};
use std::str;

use super::*;

// ========================================================================= //

fn read_le_u32(r: &mut impl io::Read) -> io::Result<u32> {
    let mut buf = [0; 4];
    r.read_exact(&mut buf).map(|()| u32::from_le_bytes(buf))
}

fn read_be_u32(r: &mut impl io::Read) -> io::Result<u32> {
    let mut buf = [0; 4];
    r.read_exact(&mut buf).map(|()| u32::from_be_bytes(buf))
}

fn read_be_u64(r: &mut impl io::Read) -> io::Result<u64> {
    let mut buf = [0; 8];
    r.read_exact(&mut buf).map(|()| u64::from_be_bytes(buf))
}

// ========================================================================= //

impl Header {
    /// Parses and returns the next header and its length.  Returns `Ok(None)`
    /// if we are at EOF.
    fn read<R>(
        reader: &mut R,
        variant: &mut Variant,
        name_table: &mut Vec<u8>,
    ) -> Result<Option<(Header, u64)>>
    where
        R: Read,
    {
        // Read header
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

        // Parse identifier and size
        let mut identifier = buffer[0..16].to_vec();
        while identifier.last() == Some(&b' ') {
            identifier.pop();
        }
        let mut size = parse_number("file size", &buffer[48..58], 10)?;
        let mut header_len = ENTRY_HEADER_LEN as u64;

        // Parse GNU style special identifiers
        if *variant != Variant::BSD && identifier.starts_with(b"/") {
            *variant = Variant::GNU;
            if identifier == GNU_SYMBOL_LOOKUP_TABLE_ID.as_bytes()
                || identifier == GNU_SYMBOL_LOOKUP_TABLE_64BIT_ID.as_bytes()
            {
                io::copy(&mut reader.by_ref().take(size), &mut io::sink())?;
                return Ok(Some((Header::new(identifier, size), header_len)));
            } else if identifier == GNU_NAME_TABLE_ID.as_bytes() {
                if !name_table.is_empty() {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "found duplicate name table",
                    ));
                }
                *name_table = vec![0; size as usize];
                reader.read_exact(name_table as &mut [u8]).map_err(|err| {
                    annotate(err, "failed to read name table")
                })?;
                return Ok(Some((Header::new(identifier, size), header_len)));
            }
            let start = parse_number("GNU filename index", &buffer[1..16], 10)?
                as usize;
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

        // Parse misc fields
        let mtime = parse_number("timestamp", &buffer[16..28], 10)?;
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

        // Parse BSD style special identifiers
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
            if identifier == BSD_SYMBOL_LOOKUP_TABLE_ID.as_bytes()
                || identifier == BSD_SORTED_SYMBOL_LOOKUP_TABLE_ID.as_bytes()
            {
                io::copy(&mut reader.by_ref().take(size), &mut io::sink())?;
                return Ok(Some((Header::new(identifier, size), header_len)));
            }
        }
        Ok(Some((
            Header {
                identifier,
                mtime,
                uid,
                gid,
                mode,
                size,
            },
            header_len,
        )))
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
        if trimmed.len() == 0 {
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

// ========================================================================= //

struct HeaderAndLocation {
    header: Header,
    header_start: u64,
    data_start: u64,
}

// ========================================================================= //

/// A structure for reading archives.
pub struct Archive<R: Read> {
    reader: R,
    variant: Variant,
    symbol_table_variant: Option<SymbolTableVariant>,
    name_table: Vec<u8>,
    entry_headers: Vec<HeaderAndLocation>,
    new_entry_start: u64,
    next_entry_index: usize,
    symbol_table_header: Option<HeaderAndLocation>,
    symbol_table: Option<Vec<SymbolTableEntry>>,
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
            symbol_table_variant: None,
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
    pub fn variant(&self) -> Variant { self.variant }

    /// Unwrap this archive reader, returning the underlying reader object.
    pub fn into_inner(self) -> Result<R> { Ok(self.reader) }

    fn is_name_table_id(&self, identifier: &[u8]) -> bool {
        self.variant == Variant::GNU
            && identifier == GNU_NAME_TABLE_ID.as_bytes()
    }

    fn is_symbol_lookup_table_id(
        &self,
        identifier: &[u8],
    ) -> Option<SymbolTableVariant> {
        match self.variant {
            Variant::BSD
                if identifier == BSD_SYMBOL_LOOKUP_TABLE_ID.as_bytes()
                    || identifier
                        == BSD_SORTED_SYMBOL_LOOKUP_TABLE_ID.as_bytes() =>
            {
                Some(SymbolTableVariant::BSD)
            }
            Variant::GNU
                if identifier == GNU_SYMBOL_LOOKUP_TABLE_ID.as_bytes() =>
            {
                Some(SymbolTableVariant::GNU)
            }
            Variant::GNU
                if identifier
                    == GNU_SYMBOL_LOOKUP_TABLE_64BIT_ID.as_bytes() =>
            {
                Some(SymbolTableVariant::GNU64BIT)
            }
            _ => None,
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
                    if let Some(symbol_table_variant) =
                        self.is_symbol_lookup_table_id(header.identifier())
                    {
                        if self.symbol_table_variant.is_some() {
                            return Some(Err(Error::new(
                                ErrorKind::InvalidData,
                                "Found more than one symbol table",
                            )));
                        }
                        self.symbol_table_variant = Some(symbol_table_variant);
                        self.symbol_table_header = Some(HeaderAndLocation {
                            header: header,
                            header_start: header_start,
                            data_start: header_start + header_len,
                        });
                        continue;
                    }
                    if self.next_entry_index == self.entry_headers.len() {
                        self.entry_headers.push(HeaderAndLocation {
                            header: header,
                            header_start: header_start,
                            data_start: header_start + header_len,
                        });
                    }
                    let header =
                        &self.entry_headers[self.next_entry_index].header;
                    self.next_entry_index += 1;
                    return Some(Ok(Entry {
                        header: header,
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
                if let Some(symbol_table_variant) =
                    self.is_symbol_lookup_table_id(header.identifier())
                {
                    if self.symbol_table_variant.is_some() {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Found more than one symbol table",
                        ));
                    }
                    self.symbol_table_variant = Some(symbol_table_variant);
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
        if size % 2 != 0 {
            self.padding = true;
        } else {
            self.padding = false;
        }
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
            match self.symbol_table_variant {
                None => unreachable!(),
                Some(SymbolTableVariant::GNU) => {
                    let num_symbols = read_be_u32(&mut reader)? as usize;
                    let mut symbol_offsets =
                        Vec::<u32>::with_capacity(num_symbols);
                    for _ in 0..num_symbols {
                        let offset = read_be_u32(&mut reader)?;
                        symbol_offsets.push(offset);
                    }
                    let mut symbol_table = Vec::with_capacity(num_symbols);
                    for offset in symbol_offsets.into_iter() {
                        let mut symbol_name = Vec::<u8>::new();
                        reader.read_until(0, &mut symbol_name)?;
                        if symbol_name.last() == Some(&0) {
                            symbol_name.pop();
                        }
                        symbol_name.shrink_to_fit();
                        symbol_table.push(SymbolTableEntry {
                            symbol_name,
                            file_offset: offset as u64,
                        });
                    }
                    self.symbol_table = Some(symbol_table);
                }
                Some(SymbolTableVariant::GNU64BIT) => {
                    let num_symbols = read_be_u64(&mut reader)? as usize;
                    let mut symbol_offsets =
                        Vec::<u64>::with_capacity(num_symbols);
                    for _ in 0..num_symbols {
                        let offset = read_be_u64(&mut reader)?;
                        symbol_offsets.push(offset);
                    }
                    let mut symbol_table = Vec::with_capacity(num_symbols);
                    for offset in symbol_offsets.into_iter() {
                        let mut symbol_name = Vec::<u8>::new();
                        reader.read_until(0, &mut symbol_name)?;
                        if symbol_name.last() == Some(&0) {
                            symbol_name.pop();
                        }
                        symbol_name.shrink_to_fit();
                        symbol_table.push(SymbolTableEntry {
                            symbol_name,
                            file_offset: offset,
                        });
                    }
                    self.symbol_table = Some(symbol_table);
                }
                Some(SymbolTableVariant::BSD) => {
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
                    for (str_start, file_offset) in symbol_offsets.into_iter()
                    {
                        let str_start = str_start as usize;
                        let mut str_end = str_start;
                        while str_end < str_table_data.len()
                            && str_table_data[str_end] != 0u8
                        {
                            str_end += 1;
                        }
                        let string = &str_table_data[str_start..str_end];
                        symbol_table.push(SymbolTableEntry {
                            symbol_name: string.to_vec(),
                            file_offset: file_offset as u64,
                        });
                    }
                    self.symbol_table = Some(symbol_table);
                }
            }
        }
        // Resume our previous position in the file.
        if self.entry_headers.len() > 0 {
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
        Ok(Symbols {
            archive: self,
            index: 0,
        })
    }
}

// ========================================================================= //

/// Representation of an archive entry.
///
/// `Entry` objects implement the `Read` trait, and can be used to extract the
/// data from this archive entry.  If the underlying reader supports the `Seek`
/// trait, then the `Entry` object supports `Seek` as well.
pub struct Entry<'a, R: 'a + Read> {
    header: &'a Header,
    reader: &'a mut R,
    length: u64,
    position: u64,
}

impl<'a, R: 'a + Read> Entry<'a, R> {
    /// Returns the header for this archive entry.
    pub fn header(&self) -> &Header { self.header }
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

// ========================================================================= //

/// An entry in the symbol table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolTableEntry {
    /// The name of the symbol.
    pub symbol_name: Vec<u8>,

    /// The file offset of the object file containing the symbol.
    pub file_offset: u64,
}

/// An iterator over the symbols in the symbol table of an archive.
pub struct Symbols<'a, R: 'a + Read> {
    archive: &'a Archive<R>,
    index: usize,
}

impl<'a, R: Read> Iterator for Symbols<'a, R> {
    type Item = &'a SymbolTableEntry;

    fn next(&mut self) -> Option<&'a SymbolTableEntry> {
        if let Some(ref table) = self.archive.symbol_table {
            if self.index < table.len() {
                let next = &table[self.index];
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

// ========================================================================= //

fn annotate(error: io::Error, msg: &str) -> io::Error {
    let kind = error.kind();
    if let Some(inner) = error.into_inner() {
        io::Error::new(kind, format!("{}: {}", msg, inner))
    } else {
        io::Error::new(kind, msg)
    }
}

// ========================================================================= //

#[cfg(test)]
mod tests {
    use super::{Archive, Variant};
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
        let reader = SlowReader {
            current_position: 0,
            buffer: input.as_bytes(),
        };
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
        let symbols = archive
            .symbols()
            .unwrap()
            .map(|sym| &*sym.symbol_name)
            .collect::<Vec<&[u8]>>();
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
        let symbols = archive
            .symbols()
            .unwrap()
            .map(|sym| &*sym.symbol_name)
            .collect::<Vec<&[u8]>>();
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
        let symbols = archive
            .symbols()
            .unwrap()
            .map(|sym| &*sym.symbol_name)
            .collect::<Vec<&[u8]>>();
        let expected: Vec<&[u8]> = vec![b"foobar", b"baz", b"quux"];
        assert_eq!(symbols, expected);
    }
}

// ========================================================================= //
