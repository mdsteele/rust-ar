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
        self.validate()?;
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
        deterministic: bool,
        writer: &mut W,
        names: &HashMap<Vec<u8>, usize>,
    ) -> Result<()>
    where
        W: Write,
    {
        self.validate()?;
        if self.identifier.len() > 15 {
            let offset = names[&self.identifier];
            write!(writer, "/{:<15}", offset)?;
        } else {
            writer.write_all(&self.identifier)?;
            writer.write_all(b"/")?;
            writer.write_all(&vec![b' '; 15 - self.identifier.len()])?;
        }

        if deterministic {
            write!(
                writer,
                "{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                0, 0, 0, 0o644, self.size
            )?;
        } else {
            write!(
                writer,
                "{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                self.mtime, self.uid, self.gid, self.mode, self.size
            )?;
        }

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
    pub fn new(writer: W) -> Result<Builder<W>> {
        Self::new_with_symbol_table(writer, BTreeMap::new())
    }

    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.
    ///
    /// The second argument is a map from file identifier to the name of all symbols in the file.
    pub fn new_with_symbol_table(
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
                8 * u32::try_from(symbol_count)
                    .map_err(|_| err!("Too many symbols `{}`", symbol_count))?
                ),
            )?;
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
                    err!(
                        "Total symbol name size too much. `{:#x}` bytes",
                        total_symbol_size
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
                    .map_err(|_| err!("Archive larger than 4GB"))?
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
            bail!("Wrong file size (header.size() = `{}`, actual = `{}`)",
                  header.size(), actual_size)
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
            err!("Given path doesn't have a file name")
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
#[derive(Copy, Clone)]
pub enum GnuSymbolTableFormat {
    /// A 32bit table (`/` in archive entry)
    ///
    /// This table is used for archives where the entire archive fits inside 4gb.
    Size32,

    /// A 64bit offset table (`/SYM64` in archive entry)
    ///
    /// This table is used for archives that will be larger than 4gb.
    Size64,
}

impl GnuSymbolTableFormat {
    fn wordsize(self) -> usize {
        match self {
            Self::Size32 => std::mem::size_of::<u32>(),
            Self::Size64 => std::mem::size_of::<u64>(),
        }
    }

    fn entry_name(self) -> &'static str {
        match self {
            Self::Size32 => GNU_SYMBOL_LOOKUP_TABLE_ID,
            Self::Size64 => GNU_SYMBOL_LOOKUP_TABLE_64BIT_ID,
        }
    }
}

/// Builder for GNU archive format
///
/// # TL;DR
/// The GNU format is a backwards incompatible archive format that diverges from the legacy Unix
/// archive format in the following significant ways:
///
/// 1) It can contain a binary symbol table that needs to be the first member of the archive.
///    This table can contain either 32bit or 64bit offsets pointing to the entities that symbols
///    relate to.
///
///    Unlike the BSD tables the GNU tables are _somewhat_ more formally defined and are simpler in
///    construction.
///
/// 2) The handling of extended strings is done with a string lookup table (either as the first of
///    second member) which is little more than a large string array.
///
/// 3) Extensions exist to create a rare format known as a thin-archive.
///
/// 4) GNU archives have a formal [deterministic mode](#deterministic-archives) that is important
///    for build systems and toolchains.
///
/// Most tools outside of BSD targets tend to use GNU format as the defacto standard, and it is
/// well-supported by LLVM and GNU toolchains. More subtle variants of this format exist such as
/// the unimplemented Microsoft extended ECOFF archive.
///
/// # Layout
/// Except where indicated, the metadata for the archive is typically encoded as ascii strings. All
/// ascii strings in an archive are padded to the length of the given field with ascii space `0x20`
/// as the fill value. This gives an archive a general fixed format look if opened in a text
/// editor.
///
/// Data is emplaced inline directly after a header record, no manipulations are done on data
/// stored in an archive, and there are no restrictions on what data can be stored in an archive.
/// Data might have a padding character (`\n`) added if the entity would be on an odd byte
/// boundary, but this is purely an internal detail of the format and not visible in any metadata.
///
/// **Header**
///
/// | Section         | Type                |
/// |-----------------|---------------------|
/// | Magic signature | Literal `!<arch>\n` |
///
/// **Entity Header**
///
/// | Section | Type           | Notes                                                                                            |
/// |---------|----------------|--------------------------------------------------------------------------------------------------|
/// | Name    | `[u8; 16]`     | Gnu handles strings in a manner that _effectively_ reduces this to 15 bytes                      |
/// | MTime   | `[u8; 12]`     | Seconds since the Unix epoch. Often `0` as per [deterministic archives](#deterministic-archives) |
/// | Uid     | `[u8; 6]`      | Unix plain user id. Often `0` as per [deterministic archives](#deterministic-archives)           |
/// | Gid     | `[u8; 6]`      | Unix plain group id. Often `0` as per [deterministic archives](#deterministic-archives)          |
/// | Mode    | `[u8; 8]`      | Unix file mode in Octal. Often `0` as per [deterministic archives](#deterministic-archives)      |
/// | Size    | `[u8; 10]`     | Entity data size in bytes, the size _does not reflect_ any padding                               |
/// | End     | Literal `\`\n` | Marks the end of the entity header                                                               |
///
/// **Symbol table (if present)**
///
/// Symbol tables are prepended with an entity header, although most implementations choose to make
/// the header all spaces in contrast to general header format for [deterministic
/// archives](#Deterministic Archives) but with the same general effect.
///
/// The name for the entity for the symbol table is either `//` or `/SYM64/` dependent on if the
/// overall size of the archive crosses the maximum addressable size allowed by 32 bits.
///
/// | Section  | Type              | Notes                                                   |
/// |----------|-------------------|---------------------------------------------------------|
/// | Num syms | `u32` / `u64`     | _Generally_ `u32` but can be `u64` for > 4Gb archives   |
/// | Offsets  | `[u32]` / `[u64]` | Pointer from a symbol to the relevant archive entity    |
/// | Names    | `[c_str]`         | The name of each symbol as a plain C style string array |
///
/// **Extended strings (if present)**
///
/// GNU archives generally encode names inline in the format `/some_name.o/`.
///
/// The bracketed `/` pairing allows GNU archives to contain embedded spaces and other metachars
/// (excluding `/` itself).
///
/// If the name is _greater than_ 15 bytes it is encoded as offset number into a string table. The
/// string table is one of the first few members in the archive and is given as strings separated
/// by the byte sequence `[0x2F, 0x0A]` (or `\\/n` in ascii).
/// No padding is done in the string table itself and the offset written to the entity header is zero
/// based from the start of the string table.
///
/// The entity name for the string table is formatted as `/#offset`, for example, for an extended
/// name starting at offset `4853` the value written to the entity header becomes `/#4853`
///
/// ## Deterministic Archives
/// The existence of several variables in entity headers make the format poorly suited to
/// consistent generation of archives. This confuses toolchains which may interpret frequently
/// changing headers as a change to the overall archive and force needless recomputations.
///
/// As such, a backwards compatible extension exists for GNU archives where all variable fields not
/// directly related to an entities data are set to ascii `0`. This is known as deterministic mode
/// and is common for most modern in use unix archives (the format has long since lost its original
/// duty as a general archive format and is now mostly used for toolchain operations).
pub struct GnuBuilder<W: Write + Seek> {
    writer: W,
    deterministic: bool,
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
        writer: W,
        deterministic: bool,
        identifiers: Vec<Vec<u8>>,
        symtab_format: GnuSymbolTableFormat,
    ) -> Result<GnuBuilder<W>> {
        Self::new_with_symbol_table(writer, deterministic, identifiers, symtab_format, BTreeMap::new())
    }

    /// The third argument is a map from file identifier to the name of all symbols in the file.
    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.  The `identifiers` parameter must give
    /// the complete list of entry identifiers that will be included in this
    /// archive. The last argument is a map from file identifier to the name of
    /// all symbols in the file.
    pub fn new_with_symbol_table(
        mut writer: W,
        deterministic: bool,
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
            let wordsize = symtab_format.wordsize();
            let symbol_count: usize = symbol_table
                .iter()
                .map(|(_identifier, symbols)| symbols.len())
                .sum();
            let symbols = symbol_table
                .iter()
                .flat_map(|(_identifier, symbols)| symbols);
            let mut symbol_table_size: usize = wordsize
                + wordsize * symbol_count
                + symbols.map(|symbol| symbol.len() + 1).sum::<usize>();
            let symbol_table_needs_padding = symbol_table_size % 2 != 0;
            if symbol_table_needs_padding {
                symbol_table_size += 3; // ` /\n`
            }
            write!(writer, "{:<48}{:<10}`\n", symtab_format.entry_name(), symbol_table_size)?;
            match symtab_format {
                GnuSymbolTableFormat::Size32 => {
                    writer.write_all(&u32::to_be_bytes(
                        u32::try_from(symbol_count)
                        .map_err(|_| err!("Too many symbols for 32bit table `{}`", symbol_count))?
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
                    GnuSymbolTableFormat::Size64 => {
                        writer.write_all(&u64::to_be_bytes(0xcafebabe_deadbeef))?
                    },
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
            deterministic,
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

        ensure!(has_name,
            "Identifier `{:?}` was not in the list of identifiers passed to GnuBuilder::new()",
            String::from_utf8_lossy(header.identifier()));

        if let Some(relocs) =
            self.symbol_table_relocations.get(header.identifier())
        {
            let entry_offset = self.writer.seek(io::SeekFrom::Current(0))?;
            match self.symtab_format {
                GnuSymbolTableFormat::Size32 => {
                    let entry_offset_bytes = u32::to_be_bytes(
                        u32::try_from(entry_offset)
                            .map_err(|_| err!("Archive larger than 4GB"))?
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

        header.write_gnu(self.deterministic, &mut self.writer, &self.long_names)?;
        let actual_size = io::copy(&mut data, &mut self.writer)?;
        if actual_size != header.size() {
            bail!("Wrong file size (header.size() = `{}`, actual = `{}`)", header.size(), actual_size);
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
            err!("Given path doesn't have a file name")
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
    string.to_str()
        .map(|x| x.as_bytes.to_vec())
        .ok_or_else(|| err!("Non-UTF8 file name"))
}

// ========================================================================= //

#[cfg(test)]
mod tests {
    use super::{
        Archive, Builder, GnuBuilder, GnuSymbolTableFormat, Header,
        SymbolTableEntry,
        test_support::HeaderAndData,
    };

    use pretty_assertions::assert_eq;
    use itertools::Itertools;

    use proptest::{
        prelude::*,
        collection::vec as any_vec
    };

    use rand::seq::SliceRandom;
    use rand_pcg::Pcg64Mcg;

    use std::{
        collections::BTreeMap,
        io::{Cursor, ErrorKind},
        str
    };

    #[test]
    fn build_common_archive() {
        let mut builder =
            Builder::new(Cursor::new(Vec::new())).unwrap();
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
        baz.txt         0           0     0     644     4         `\n\
        baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_bsd_archive_with_long_filenames() {
        let mut builder =
            Builder::new(Cursor::new(Vec::new())).unwrap();
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
        #1/44           0           0     0     644     48        `\n\
        and_this_is_another_very_long_filename.txt\x00\x00baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_bsd_archive_with_space_in_filename() {
        let mut builder =
            Builder::new(Cursor::new(Vec::new())).unwrap();
        let header = Header::new(b"foo bar".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap().into_inner();
        let expected = "\
        !<arch>\n\
        #1/8            0           0     0     644     12        `\n\
        foo bar\x00baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_gnu_archive() {
        let names = vec![b"baz.txt".to_vec(), b"foo.txt".to_vec()];
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            false,
            names,
            GnuSymbolTableFormat::Size32,
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
        baz.txt/        0           0     0     644     4         `\n\
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
            false,
            names,
            GnuSymbolTableFormat::Size32,
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
        /34             0           0     0     644     4         `\n\
        baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    fn build_gnu_archive_with_space_in_filename() {
        let names = vec![b"foo bar".to_vec()];
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            false,
            names,
            GnuSymbolTableFormat::Size32,
        )
        .unwrap();
        let header = Header::new(b"foo bar".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes()).unwrap();
        let actual = builder.into_inner().unwrap().into_inner();
        let expected = "\
        !<arch>\n\
        foo bar/        0           0     0     644     4         `\n\
        baz\n";
        assert_eq!(str::from_utf8(&actual).unwrap(), expected);
    }

    #[test]
    #[should_panic(
        expected = r#"Identifier `\"bar\"` was not in the list of identifiers passed to GnuBuilder::new()"#
    )]
    fn build_gnu_archive_with_unexpected_identifier() {
        let names = vec![b"foo".to_vec()];
        let mut builder = GnuBuilder::new(
            Cursor::new(Vec::new()),
            false,
            names,
            GnuSymbolTableFormat::Size32,
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
                false,
                filenames.clone(),
                GnuSymbolTableFormat::Size32,
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
        let mut builder = GnuBuilder::new_with_symbol_table(
            Cursor::new(Vec::new()),
            false,
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
        foo/            0           0     0     644     1         `\n\
        ?\n\
        foobar/         0           0     0     644     1         `\n\
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
                    entry_index: 0,
                },
                &SymbolTableEntry {
                    symbol_name: b"bazz".to_vec(),
                    entry_index: 0,
                },
                &SymbolTableEntry {
                    symbol_name: b"aaa".to_vec(),
                    entry_index: 1,
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
        let mut builder = GnuBuilder::new_with_symbol_table(
            Cursor::new(Vec::new()),
            false,
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
        foo/            0           0     0     644     1         `\n\
        ?\n\
        foobar/         0           0     0     644     1         `\n\
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
                    entry_index: 0,
                },
                &SymbolTableEntry {
                    symbol_name: b"bazz".to_vec(),
                    entry_index: 0,
                },
                &SymbolTableEntry {
                    symbol_name: b"aaa".to_vec(),
                    entry_index: 1,
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
        let mut builder = Builder::new_with_symbol_table(
            Cursor::new(Vec::new()),
            symbol_table,
        ).unwrap();
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
        foo             0           0     0     644     1         `\n\
        ?\n\
        foobar          0           0     0     644     1         `\n\
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
                    entry_index: 0,
                },
                &SymbolTableEntry {
                    symbol_name: b"bazz".to_vec(),
                    entry_index: 0,
                },
                &SymbolTableEntry {
                    symbol_name: b"aaa".to_vec(),
                    entry_index: 1,
                },
            ]
        );
    }

    #[test]
    fn build_gnu_archive_with_bad_headers() {
        let assert_err = |mutator: fn(&mut Header) -> (), msg: &str| {
            let mut builder = GnuBuilder::new(Cursor::new(vec![]), false, vec![b"ident".to_vec()], GnuSymbolTableFormat::Size32).unwrap();
            let mut header = Header::new(b"ident".to_vec(), 12345);
            mutator(&mut header);
            let err = builder.append(&header, Cursor::new(vec![])).expect_err("No error produced!");
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert_eq!(&err.into_inner().unwrap().to_string(), msg);
        };

        assert_err(|hdr| hdr.set_mtime(1234567890123), "MTime `1234567890123` > 12 digits");
        assert_err(|hdr| hdr.set_uid(1234567), "UID `1234567` > 6 digits");
        assert_err(|hdr| hdr.set_gid(1234567), "GID `1234567` > 6 digits");
        assert_err(|hdr| hdr.set_mode(0o123456712), "Mode `123456712` > 8 octal digits");
    }

    #[test]
    fn build_bsd_archive_with_bad_headers() {
        let assert_err = |mutator: fn(&mut Header) -> (), msg: &str| {
            let mut builder = Builder::new(Cursor::new(vec![])).unwrap();
            let mut header = Header::new(b"ident".to_vec(), 12345);
            mutator(&mut header);
            let err = builder.append(&header, Cursor::new(vec![])).expect_err("No error produced!");
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert_eq!(&err.into_inner().unwrap().to_string(), msg);
        };

        assert_err(|hdr| hdr.set_mtime(1234567890123), "MTime `1234567890123` > 12 digits");
        assert_err(|hdr| hdr.set_uid(1234567), "UID `1234567` > 6 digits");
        assert_err(|hdr| hdr.set_gid(1234567), "GID `1234567` > 6 digits");
        assert_err(|hdr| hdr.set_mode(0o123456712), "Mode `123456712` > 8 octal digits");
    }

    fn idents<'a>(entries: impl Iterator<Item=&'a HeaderAndData>) -> Vec<Vec<u8>> {
        entries
            .map(|HeaderAndData { header, .. }| header.identifier().to_vec())
            .collect::<Vec<_>>()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn test_any_gnu_general_archive(mut entries in any_vec(any::<HeaderAndData>(), 0..20)) {
            let mut builder = GnuBuilder::new(
                Cursor::new(Vec::new()),
                false,
                idents(entries.iter()),
                GnuSymbolTableFormat::Size32,
            )?;

            // shuffle to ensure writing entries out of order from idents is not broken
            let mut rng = Pcg64Mcg::new(0xcafef00dd15ea5e5);
            entries.shuffle(&mut rng);

            for HeaderAndData { header, data } in &entries {
                builder.append(&header, Cursor::new(data))?;
            }

            let mut raw_data = builder.into_inner()?;
            raw_data.set_position(0);

            let mut ar = Archive::new(raw_data);
            assert_eq!(ar.count_entries()?, entries.len());

            let mut actuals = entries.iter();
            while let Some(entry) = ar.next_entry() {
                let HeaderAndData { header, data } = actuals.next().unwrap();

                let mut actual_entry = entry?;
                let actual_header = actual_entry.header();
                assert_eq!(actual_header.identifier(), header.identifier());
                assert_eq!(actual_header.mtime(), header.mtime);
                assert_eq!(actual_header.uid(), header.uid);
                assert_eq!(actual_header.gid(), header.gid);
                assert_eq!(actual_header.mode(), header.mode);
                assert_eq!(actual_header.size(), header.size);
                assert_eq!(actual_header.size() as usize, data.len());

                let mut actual_data = Cursor::new(Vec::with_capacity(data.len()));
                std::io::copy(&mut actual_entry, &mut actual_data)?;
                let actual_data = actual_data.into_inner();
                assert_eq!(&actual_data, data);
            }
        }

        #[test]
        fn test_any_gnu_deterministic_archive(mut entries in any_vec(any::<HeaderAndData>(), 0..20)) {
            let mut builder = GnuBuilder::new(
                Cursor::new(Vec::new()),
                true,
                idents(entries.iter()),
                GnuSymbolTableFormat::Size32,
            )?;

            // shuffle to ensure writing entries out of order from idents is not broken
            let mut rng = Pcg64Mcg::new(0xcafef00dd15ea5e5);
            entries.shuffle(&mut rng);

            for HeaderAndData { header, data } in &entries {
                builder.append(&header, Cursor::new(data))?;
            }

            let mut raw_data = builder.into_inner()?;
            raw_data.set_position(0);

            let mut ar = Archive::new(raw_data);
            assert_eq!(ar.count_entries()?, entries.len());

            let mut actuals = entries.iter();
            while let Some(entry) = ar.next_entry() {
                let HeaderAndData { header, data } = actuals.next().unwrap();

                let mut actual_entry = entry?;
                let actual_header = actual_entry.header();
                assert_eq!(actual_header.identifier(), header.identifier());
                assert_eq!(actual_header.mtime(), 0);
                assert_eq!(actual_header.uid(), 0);
                assert_eq!(actual_header.gid(), 0);
                assert_eq!(actual_header.mode(), 0o644);
                assert_eq!(actual_header.size(), header.size);
                assert_eq!(actual_header.size() as usize, data.len());

                let mut actual_data = Cursor::new(Vec::with_capacity(data.len()));
                std::io::copy(&mut actual_entry, &mut actual_data)?;
                let actual_data = actual_data.into_inner();
                assert_eq!(&actual_data, data);
            }
        }

        #[test]
        fn test_any_gnu_general_archive_with_syms(
            test_data in any_vec((
                any::<HeaderAndData>(),
                any_vec(r#"\PC{1, 50}"#, 0..6)
            ), 0..20)
        ) {
            let syms = test_data.iter()
                .filter_map(|(hdr, syms)| if syms.is_empty() {
                    None
                } else {
                    Some((hdr.header.identifier().to_vec(), syms.iter().map(|x| x.as_bytes().to_vec()).collect::<Vec<_>>()))
                })
                .collect::<BTreeMap<_, Vec<Vec<u8>>>>();

            let mut builder = GnuBuilder::new_with_symbol_table(
                Cursor::new(Vec::new()),
                true,
                idents(test_data.iter().map(|(hdr, _)| hdr)),
                GnuSymbolTableFormat::Size32,
                syms.clone()
            )?;

            let mut entries = test_data.iter().map(|(hdr, _)| hdr.clone()).collect::<Vec<_>>();

            // shuffle to ensure writing entries out of order from idents is not broken
            let mut rng = Pcg64Mcg::new(0xcafef00dd15ea5e5);
            entries.shuffle(&mut rng);

            for HeaderAndData { header, data } in entries {
                builder.append(&header, Cursor::new(data))?;
            }

            let mut raw_data = builder.into_inner()?;
            raw_data.set_position(0);

            let mut ar = Archive::new(raw_data);
            assert_eq!(ar.count_entries()?, test_data.len());

            let expected_syms = test_data.iter()
                .map(|(HeaderAndData { header, .. }, syms)| (header.identifier().clone(), syms))
                .flat_map(|(id, syms)| syms.iter().map(move |sym| (sym.as_bytes().to_vec(), id.clone())))
                .into_group_map();

            let actual_syms = ar.symbols()?.cloned().collect::<Vec<_>>();
            assert_eq!(actual_syms.len(), syms.iter().map(|(_, v)| v.len()).sum());

            for SymbolTableEntry { symbol_name, entry_index } in actual_syms {
                let entry_ids = expected_syms.get(&symbol_name).expect("Presented Symbol not in archive?");
                let entry = ar.jump_to_entry(entry_index)?;

                assert!(entry_ids.contains(&entry.header().identifier()));
            }
        }
    }
}

// ========================================================================= //
