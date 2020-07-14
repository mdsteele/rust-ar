use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Error, ErrorKind, Read, Result, Seek, Write};
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
pub struct Builder<W: Write + Seek> {
    writer: W,
    symbol_table_relocations: HashMap<Vec<u8>, Vec<u64>>,
}

impl<W: Write + Seek> Builder<W> {
    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.
    pub fn new(
        mut writer: W,
        symbol_table: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
    ) -> Result<Builder<W>> {
        writer.write_all(GLOBAL_HEADER)?;

        let mut symbol_table_relocations: HashMap<Vec<u8>, Vec<u64>> =
            HashMap::with_capacity(symbol_table.len());
        if !symbol_table.is_empty() {
            let symbol_count: usize = symbol_table
                .iter()
                .map(|(_identifier, symbols)| symbols.len())
                .sum();
            let total_symbol_size: usize = symbol_table
                .iter()
                .flat_map(|(_identifier, symbols)| symbols)
                .map(|symbol| symbol.len() + 1)
                .sum::<usize>();
            let mut symbol_table_size: usize =
                4 + 8 * symbol_count + 4 + total_symbol_size;
            let symbol_table_needs_padding = symbol_table_size % 2 != 0;
            if symbol_table_needs_padding {
                symbol_table_size += 3; // ` /\n`
            }
            write!(
                writer,
                "#1/12           0           0     0     0       {:<10}`\n",
                symbol_table_size + 12
            )?;
            writer.write_all(&*b"__.SYMDEF\0\0\0")?;
            writer.write_all(&u32::to_le_bytes(
                8 * u32::try_from(symbol_count).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "More than 4 billion symbols??? There are {}",
                            symbol_count
                        ),
                    )
                })?,
            ))?;
            let mut str_offset = 0;
            for (identifier, symbol) in
                symbol_table.iter().flat_map(|(identifier, symbols)| {
                    symbols.iter().map(move |symbol| (identifier, symbol))
                })
            {
                writer.write_all(&u32::to_le_bytes(str_offset))?;
                str_offset += symbol.len() as u32 + 1;
                symbol_table_relocations
                    .entry(identifier.clone())
                    .or_default()
                    .push(writer.seek(io::SeekFrom::Current(0))?);
                writer.write_all(&u32::to_le_bytes(0xcafebabe))?;
            }
            writer.write_all(&u32::to_le_bytes(
                u32::try_from(total_symbol_size).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "More than 4GB of symbol strings??? There are 0x{:x} bytes",
                            total_symbol_size
                        ),
                    )
                })?,
            ))?;
            for symbol in symbol_table
                .iter()
                .flat_map(|(_identifier, symbols)| symbols)
            {
                writer.write_all(symbol)?;
                writer.write_all(&[0])?;
            }
            if symbol_table_needs_padding {
                writer.write_all(b" /\n")?;
            }
        }

        Ok(Builder {
            writer,
            symbol_table_relocations,
        })
    }

    /// Unwrap this archive builder, returning the underlying writer object.
    pub fn into_inner(self) -> Result<W> { Ok(self.writer) }

    /// Adds a new entry to this archive.
    pub fn append<R: Read>(
        &mut self,
        header: &Header,
        mut data: R,
    ) -> Result<()> {
        if let Some(relocs) =
            self.symbol_table_relocations.get(header.identifier())
        {
            let entry_offset = self.writer.seek(io::SeekFrom::Current(0))?;
            let entry_offset_bytes = u32::to_le_bytes(
                u32::try_from(entry_offset)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, format!("Archive is bigger than 4GB. It is already 0x{:x} bytes.", entry_offset)))?
            );
            for &reloc_offset in relocs {
                self.writer.seek(io::SeekFrom::Start(reloc_offset))?;
                self.writer.write_all(&entry_offset_bytes)?;
            }
            self.writer.seek(io::SeekFrom::Start(entry_offset))?;
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

/// The format of the GNU symbol table.
#[allow(missing_docs)]
pub enum GnuSymbolTableFormat {
    Size32,
    Size64,
}

/// A structure for building GNU-variant archives (the archive format typically
/// used on e.g. GNU/Linux and Windows systems).
///
/// This structure has methods for building up an archive from scratch into any
/// arbitrary writer.
pub struct GnuBuilder<W: Write + Seek> {
    writer: W,
    short_names: HashSet<Vec<u8>>,
    long_names: HashMap<Vec<u8>, usize>,
    symtab_format: GnuSymbolTableFormat,
    symbol_table_relocations: HashMap<Vec<u8>, Vec<u64>>,
}

impl<W: Write + Seek> GnuBuilder<W> {
    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.  The `identifiers` parameter must give
    /// the complete list of entry identifiers that will be included in this
    /// archive.
    pub fn new(
        mut writer: W,
        identifiers: Vec<Vec<u8>>,
        symtab_format: GnuSymbolTableFormat,
        symbol_table: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
    ) -> Result<GnuBuilder<W>> {
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

        writer.write_all(GLOBAL_HEADER)?;

        let mut symbol_table_relocations: HashMap<Vec<u8>, Vec<u64>> =
            HashMap::with_capacity(symbol_table.len());
        if !symbol_table.is_empty() {
            let int_size = match symtab_format {
                GnuSymbolTableFormat::Size32 => 4,
                GnuSymbolTableFormat::Size64 => 8,
            };
            let symbol_count: usize = symbol_table
                .iter()
                .map(|(_identifier, symbols)| symbols.len())
                .sum();
            let symbols = symbol_table
                .iter()
                .flat_map(|(_identifier, symbols)| symbols);
            let mut symbol_table_size: usize = int_size
                + int_size * symbol_count
                + symbols.map(|symbol| symbol.len() + 1).sum::<usize>();
            let symbol_table_needs_padding = symbol_table_size % 2 != 0;
            if symbol_table_needs_padding {
                symbol_table_size += 3; // ` /\n`
            }
            write!(
                writer,
                "{:<48}{:<10}`\n",
                match symtab_format {
                    GnuSymbolTableFormat::Size32 => GNU_SYMBOL_LOOKUP_TABLE_ID,
                    GnuSymbolTableFormat::Size64 =>
                        GNU_SYMBOL_LOOKUP_TABLE_64BIT_ID,
                },
                symbol_table_size
            )?;
            match symtab_format {
                GnuSymbolTableFormat::Size32 => {
                    writer.write_all(&u32::to_be_bytes(
                        u32::try_from(symbol_count).map_err(|_| {
                            Error::new(
                                ErrorKind::InvalidInput,
                                format!(
                                    "More than 4 billion symbols for a 32bit symbol table, there are {} symbols.",
                                    symbol_count
                                ),
                            )
                        })?,
                    ))?;
                }
                GnuSymbolTableFormat::Size64 => {
                    writer.write_all(&u64::to_be_bytes(
                        u64::try_from(symbol_count).unwrap(),
                    ))?;
                }
            }
            for identifier in
                symbol_table.iter().flat_map(|(identifier, symbols)| {
                    std::iter::repeat(identifier).take(symbols.len())
                })
            {
                symbol_table_relocations
                    .entry(identifier.clone())
                    .or_default()
                    .push(writer.seek(io::SeekFrom::Current(0))?);
                match symtab_format {
                    GnuSymbolTableFormat::Size32 => {
                        writer.write_all(&u32::to_be_bytes(0xcafebabe))?
                    }
                    GnuSymbolTableFormat::Size64 => writer
                        .write_all(&u64::to_be_bytes(0xcafebabe_deadbeef))?,
                }
            }
            for symbol in symbol_table
                .iter()
                .flat_map(|(_identifier, symbols)| symbols)
            {
                writer.write_all(symbol)?;
                writer.write_all(b"\0")?;
            }
            if symbol_table_needs_padding {
                writer.write_all(b" /\n")?;
            }
        }

        if !long_names.is_empty() {
            write!(
                writer,
                "{:<48}{:<10}`\n",
                GNU_NAME_TABLE_ID, name_table_size
            )?;
            let mut entries: Vec<(usize, &[u8])> = long_names
                .iter()
                .map(|(id, &start)| (start, id.as_slice()))
                .collect();
            entries.sort();
            for (_, id) in entries {
                writer.write_all(id)?;
                writer.write_all(b"/\n")?;
            }
            if name_table_needs_padding {
                writer.write_all(b" /\n")?;
            }
        }

        Ok(GnuBuilder {
            writer,
            short_names,
            long_names,
            symtab_format,
            symbol_table_relocations,
        })
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

        if let Some(relocs) =
            self.symbol_table_relocations.get(header.identifier())
        {
            let entry_offset = self.writer.seek(io::SeekFrom::Current(0))?;
            match self.symtab_format {
                GnuSymbolTableFormat::Size32 => {
                    let entry_offset_bytes = u32::to_be_bytes(
                        u32::try_from(entry_offset)
                            .map_err(|_| Error::new(ErrorKind::InvalidInput, format!("Archive is bigger than 4GB. It is already 0x{:x} bytes.", entry_offset)))?
                    );
                    for &reloc_offset in relocs {
                        self.writer.seek(io::SeekFrom::Start(reloc_offset))?;
                        self.writer.write_all(&entry_offset_bytes)?;
                    }
                }
                GnuSymbolTableFormat::Size64 => {
                    let entry_offset_bytes = u64::to_be_bytes(entry_offset);
                    for &reloc_offset in relocs {
                        self.writer.seek(io::SeekFrom::Start(reloc_offset))?;
                        self.writer.write_all(&entry_offset_bytes)?;
                    }
                }
            }
            self.writer.seek(io::SeekFrom::Start(entry_offset))?;
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
    use super::{
        Archive, Builder, GnuBuilder, GnuSymbolTableFormat, Header,
        SymbolTableEntry,
    };
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::str;

    #[test]
    fn build_common_archive() {
        let mut builder =
            Builder::new(Cursor::new(Vec::new()), BTreeMap::new()).unwrap();
        let mut header1 = Header::new(b"foo.txt".to_vec(), 7);
        header1.set_mtime(1487552916);
        header1.set_uid(501);
        header1.set_gid(20);
        header1.set_mode(0o100644);
        builder.append(&header1, "foobar\n".as_bytes()).unwrap();
        let header2 = Header::new(b"baz.txt".to_vec(), 4);
        builder.append(&header2, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap().into_inner();
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
        let mut builder =
            Builder::new(Cursor::new(Vec::new()), BTreeMap::new()).unwrap();
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
        let actual = builder.into_inner().unwrap().into_inner();
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
        let mut builder =
            Builder::new(Cursor::new(Vec::new()), BTreeMap::new()).unwrap();
        let header = Header::new(b"foo bar".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap().into_inner();
        let expected = "\
        !<arch>\n\
        #1/8            0           0     0     0       12        `\n\
        foo bar\x00baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_gnu_archive() {
        let names = vec![b"baz.txt".to_vec(), b"foo.txt".to_vec()];
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            names,
            GnuSymbolTableFormat::Size32,
            BTreeMap::new(),
        )
        .unwrap();
        let mut header1 = Header::new(b"foo.txt".to_vec(), 7);
        header1.set_mtime(1487552916);
        header1.set_uid(501);
        header1.set_gid(20);
        header1.set_mode(0o100644);
        builder.append(&header1, "foobar\n".as_bytes()).unwrap();
        let header2 = Header::new(b"baz.txt".to_vec(), 4);
        builder.append(&header2, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap().into_inner();
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
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            names,
            GnuSymbolTableFormat::Size32,
            BTreeMap::new(),
        )
        .unwrap();
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
        let actual = builder.into_inner().unwrap().into_inner();
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
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            names,
            GnuSymbolTableFormat::Size32,
            BTreeMap::new(),
        )
        .unwrap();
        let header = Header::new(b"foo bar".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap().into_inner();
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
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            names,
            GnuSymbolTableFormat::Size32,
            BTreeMap::new(),
        )
        .unwrap();
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
            let mut builder = GnuBuilder::new(
                &mut buffer,
                filenames.clone(),
                GnuSymbolTableFormat::Size32,
                BTreeMap::new(),
            )
            .unwrap();

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

    #[test]
    fn build_gnu_archive_with_symbol_table() {
        let mut symbol_table = BTreeMap::new();
        symbol_table
            .insert(b"foo".to_vec(), vec![b"bar".to_vec(), b"bazz".to_vec()]);
        symbol_table.insert(b"foobar".to_vec(), vec![b"aaa".to_vec()]);
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            vec![b"foo".to_vec(), b"foobar".to_vec()],
            GnuSymbolTableFormat::Size32,
            symbol_table,
        )
        .unwrap();
        builder
            .append(&Header::new(b"foo".to_vec(), 1), &mut (&[b'?'] as &[u8]))
            .expect("add file");
        builder
            .append(
                &Header::new(b"foobar".to_vec(), 1),
                &mut (&[b'!'] as &[u8]),
            )
            .expect("add file");
        let actual = builder.into_inner().unwrap().into_inner();
        let expected = "!<arch>\n\
        /                                               32        `\n\
        \0\0\0\x03\
        \0\0\0d\
        \0\0\0d\
        \0\0\0�\
        bar\0bazz\0aaa\0 /\n\
        foo/            0           0     0     0       1         `\n\
        ?\n\
        foobar/         0           0     0     0       1         `\n\
        !\n";
        assert_eq!(String::from_utf8_lossy(&actual), expected);

        let mut archive = Archive::new(Cursor::new(actual));
        assert_eq!(
            archive
                .symbols()
                .unwrap()
                .collect::<Vec<&SymbolTableEntry>>(),
            vec![
                &SymbolTableEntry {
                    symbol_name: b"bar".to_vec(),
                    file_offset: 100,
                },
                &SymbolTableEntry {
                    symbol_name: b"bazz".to_vec(),
                    file_offset: 100,
                },
                &SymbolTableEntry {
                    symbol_name: b"aaa".to_vec(),
                    file_offset: 162,
                },
            ]
        );
    }

    #[test]
    fn build_gnu_archive_with_64bit_symbol_table() {
        let mut symbol_table = BTreeMap::new();
        symbol_table
            .insert(b"foo".to_vec(), vec![b"bar".to_vec(), b"bazz".to_vec()]);
        symbol_table.insert(b"foobar".to_vec(), vec![b"aaa".to_vec()]);
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            vec![b"foo".to_vec(), b"foobar".to_vec()],
            GnuSymbolTableFormat::Size64,
            symbol_table,
        )
        .unwrap();
        builder
            .append(&Header::new(b"foo".to_vec(), 1), &mut (&[b'?'] as &[u8]))
            .expect("add file");
        builder
            .append(
                &Header::new(b"foobar".to_vec(), 1),
                &mut (&[b'!'] as &[u8]),
            )
            .expect("add file");
        let actual = builder.into_inner().unwrap().into_inner();
        let expected = "!<arch>\n\
        /SYM64                                          48        `\n\
        \0\0\0\0\0\0\0\x03\
        \0\0\0\0\0\0\0t\
        \0\0\0\0\0\0\0t\
        \0\0\0\0\0\0\0�\
        bar\0bazz\0aaa\0 /\n\
        foo/            0           0     0     0       1         `\n\
        ?\n\
        foobar/         0           0     0     0       1         `\n\
        !\n";
        assert_eq!(String::from_utf8_lossy(&actual), expected);

        let mut archive = Archive::new(Cursor::new(actual));
        assert_eq!(
            archive
                .symbols()
                .unwrap()
                .collect::<Vec<&SymbolTableEntry>>(),
            vec![
                &SymbolTableEntry {
                    symbol_name: b"bar".to_vec(),
                    file_offset: 116,
                },
                &SymbolTableEntry {
                    symbol_name: b"bazz".to_vec(),
                    file_offset: 116,
                },
                &SymbolTableEntry {
                    symbol_name: b"aaa".to_vec(),
                    file_offset: 178,
                },
            ]
        );
    }

    #[test]
    fn build_bsd_archive_with_symbol_table() {
        let mut symbol_table = BTreeMap::new();
        symbol_table
            .insert(b"foo".to_vec(), vec![b"bar".to_vec(), b"bazz".to_vec()]);
        symbol_table.insert(b"foobar".to_vec(), vec![b"aaa".to_vec()]);
        let mut builder =
            Builder::new(Cursor::new(Vec::new()), symbol_table).unwrap();
        builder
            .append(&Header::new(b"foo".to_vec(), 1), &mut (&[b'?'] as &[u8]))
            .expect("add file");
        builder
            .append(
                &Header::new(b"foobar".to_vec(), 1),
                &mut (&[b'!'] as &[u8]),
            )
            .expect("add file");
        let actual = builder.into_inner().unwrap().into_inner();
        let expected = "!<arch>\n\
        #1/12           0           0     0     0       60        `\n\
        __.SYMDEF\0\0\0\
        \x18\0\0\0\
        \x00\0\0\0�\0\0\0\
        \x04\0\0\0�\0\0\0\
        \x09\0\0\0�\0\0\0\
        \x0D\0\0\0\
        bar\0bazz\0aaa\0 /\n\
        foo             0           0     0     0       1         `\n\
        ?\n\
        foobar          0           0     0     0       1         `\n\
        !\n";
        assert_eq!(String::from_utf8_lossy(&actual), expected);

        let mut archive = Archive::new(Cursor::new(actual));
        assert_eq!(
            archive
                .symbols()
                .unwrap()
                .collect::<Vec<&SymbolTableEntry>>(),
            vec![
                &SymbolTableEntry {
                    symbol_name: b"bar".to_vec(),
                    file_offset: 128,
                },
                &SymbolTableEntry {
                    symbol_name: b"bazz".to_vec(),
                    file_offset: 128,
                },
                &SymbolTableEntry {
                    symbol_name: b"aaa".to_vec(),
                    file_offset: 190,
                },
            ]
        );
    }
}

// ========================================================================= //
