//! Builder for GNU archive format
//!
//! # TL;DR
//! The GNU format is a backwards incompatible archive format that diverges from the legacy Unix
//! archive format in the following significant ways:
//!
//! 1) It can contain a binary symbol table that needs to be the first member of the archive.
//!    This table can contain either 32bit or 64bit offsets pointing to the entities that symbols
//!    relate to.
//!
//!    Unlike the BSD tables the GNU tables are _somewhat_ more formally defined and are simpler in
//!    construction.
//!
//! 2) The handling of extended strings is done with a string lookup table (either as the first of
//!    second member) which is little more than a large string array.
//!
//! 3) Extensions exist to create a rare format known as a thin-archive.
//!
//! 4) GNU archives have a formal [deterministic mode](#deterministic-archives) that is important
//!    for build systems and toolchains.
//!
//! Most tools outside of BSD targets tend to use GNU format as the defacto standard, and it is
//! well-supported by LLVM and GNU toolchains. More subtle variants of this format exist such as
//! the Microsoft extended ECOFF archive, which is not implemented by rust-ar.
//!
//! # Layout
//! Except where indicated, the metadata for the archive is typically encoded as ascii strings. All
//! ascii strings in an archive are padded to the length of the given field with ascii space `0x20`
//! as the fill value. This gives an archive a general fixed format look if opened in a text
//! editor.
//!
//! Data is emplaced inline directly after a header record, no manipulations are done on data
//! stored in an archive, and there are no restrictions on what data can be stored in an archive.
//! Data has a padding character (`\n`) added if the entity would be on an odd byte
//! boundary, but this is purely an internal detail of the format and not visible in any metadata.
//!
//! **Header**
//!
//! | Section         | Type                |
//! |-----------------|---------------------|
//! | Magic signature | Literal `!<arch>\n` |
//!
//! **Entity Header**
//!
//! | Section | Type           | Notes                                                                                            |
//! |---------|----------------|--------------------------------------------------------------------------------------------------|
//! | Name    | `[u8; 16]`     | Gnu handles strings in a manner that _effectively_ reduces this to 15 bytes                      |
//! | MTime   | `[u8; 12]`     | Seconds since the Unix epoch. Often `0` as per [deterministic archives](#deterministic-archives) |
//! | Uid     | `[u8; 6]`      | Unix plain user id. Often `0` as per [deterministic archives](#deterministic-archives)           |
//! | Gid     | `[u8; 6]`      | Unix plain group id. Often `0` as per [deterministic archives](#deterministic-archives)          |
//! | Mode    | `[u8; 8]`      | Unix file mode in Octal. Often `0` as per [deterministic archives](#deterministic-archives)      |
//! | Size    | `[u8; 10]`     | Entity data size in bytes, the size _does not reflect_ any padding                               |
//! | End     | Literal `\`\n` | Marks the end of the entity header                                                               |
//!
//! **Symbol table (if present)**
//!
//! Symbol tables are prepended with an entity header, although most implementations choose to make
//! the header all spaces in contrast to general header format for [deterministic
//! archives](#Deterministic Archives) but with the same general effect.
//!
//! The name for the entity for the symbol table is either `//` or `/SYM64/` dependent on if the
//! overall size of the archive crosses the maximum addressable size allowed by 32 bits.
//!
//! | Section  | Type              | Notes                                                   |
//! |----------|-------------------|---------------------------------------------------------|
//! | Num syms | `u32` / `u64`     | _Generally_ `u32` but can be `u64` for > 4Gb archives   |
//! | Offsets  | `[u32]` / `[u64]` | Pointer from a symbol to the relevant archive entity    |
//! | Names    | `[c_str]`         | The name of each symbol as a plain C style string array |
//!
//! **Extended strings (if present)**
//!
//! GNU archives generally encode names inline in the format `/some_name.o/`.
//!
//! The bracketed `/` pairing allows GNU archives to contain embedded spaces and other metachars
//! (excluding `/` itself).
//!
//! If the name is _greater than_ 15 bytes it is encoded as offset number into a string table. The
//! string table is one of the first few members in the archive and is given as strings separated
//! by the byte sequence `[0x2F, 0x0A]` (or `\\/n` in ascii).
//! No padding is done in the string table itself and the offset written to the entity header is zero
//! based from the start of the string table.
//!
//! The entity name for the string table is formatted as `/#offset`, for example, for an extended
//! name starting at offset `4853` the value written to the entity header becomes `/#4853`
//!
//! ## Deterministic Archives
//! The existence of several variables in entity headers make the format poorly suited to
//! consistent generation of archives. This confuses toolchains which may interpret frequently
//! changing headers as a change to the overall archive and force needless recomputations.
//!
//! As such, a backwards compatible extension exists for GNU archives where all variable fields not
//! directly related to an entities data are set to ascii `0`. This is known as deterministic mode
//! and is common for most modern in use unix archives (the format has long since lost its original
//! duty as a general archive format and is now mostly used for toolchain operations).
use super::*;
use private::{ArchiveBuilderData, ArchiveBuilderSections, BaseBuilder};

/// The limit of the file size before the symtab is switched up to `SYM64`
const GNU_STD_SYMTAB_LIMIT: u64 = u32::MAX as u64;

/// The size of the pointer / offset in a standard symtab
const GNU_STD_SYMTAB_PTR: u64 = size_of::<u32>() as u64;

/// The size of the pointer / offset in a 64bit symtab
const GNU_64BIT_SYMTAB_PTR: u64 = size_of::<u64>() as u64;

/// The pad added to the string table if its not a power of 2 in size
const GNU_STRTAB_PAD: &[u8] = b" /\n";

/// The pad added to the names in the symbol table if it is not a power of 2 in size
const GNU_SYMTAB_NAMES_PAD: &[u8] = b"\n";

/// The length of the header that the string table uses
const GNU_STRTAB_HDR_PAD_LEN: usize = ENTRY_HEADER_LEN
    - (ENTRY_NAME_MAX_LEN + HEADER_SIZE_LEN + HEADER_END_MARKER_LEN);

/// The GNU string table header format, which is _almost_ like a normal header but lacks fields
const GNU_STRTAB_HDR_PAD: [u8; GNU_STRTAB_HDR_PAD_LEN] =
    [HEADER_FILL_BYTE; GNU_STRTAB_HDR_PAD_LEN];

/// The blank empty header
const EMPTY_HEADER: [u8; ENTRY_HEADER_LEN] = [HEADER_FILL_BYTE; ENTRY_HEADER_LEN];

/// A structure for building GNU-variant archives (the archive format typically
/// used on GNU/Linux and Windows systems).
///
/// This structure has methods for building up an archive from scratch into any
/// arbitrary writer.
pub struct GnuBuilder {
    deterministic: bool,
    generate_symbol_table: bool,
    strtab: ArchiveBuilderData,
    have_strtab: bool,
    symbols: Vec<u64>,
    symbol_names: ArchiveBuilderData,
    entities: ArchiveBuilderData,
}

impl Default for GnuBuilder {
    fn default() -> Self {
        const DEFAULT_SPILL_SIZE: usize = 2 * 1024 * 1024;
        GnuBuilder::new(DEFAULT_SPILL_SIZE, true, true)
    }
}

/// Used specifically in the computation of final archive layout w.r.t string and symbol tables
struct MetadataParams {
    kind: SymbolTableVariant,
    name: &'static [u8; ENTRY_NAME_MAX_LEN],
    offset: u64,
    wordsize: u64
}

impl GnuBuilder {
    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.  The `identifiers` parameter must give
    /// the complete list of entry identifiers that will be included in this
    /// archive.
    pub fn new(spill_size: usize, deterministic: bool, generate_symbol_table: bool) -> Self {
        // These are empirical from scanning a large body of archive files in a build system
        let strtab_spill = ((spill_size as f64) * 0.05).ceil() as usize;
        let mut symbol_spill = ((spill_size as f64) * 0.15).ceil() as usize;
        let mut entity_spill = ((spill_size as f64) * 0.80).ceil() as usize;

        if !generate_symbol_table {
            entity_spill += symbol_spill;
            symbol_spill = 0;
        }

        assert!(strtab_spill < spill_size, "Strtab spill < spill_size");
        assert!(symbol_spill < spill_size, "Symbol spill < spill_size");
        assert!(entity_spill < spill_size, "Entity spill < spill_size");

        // Reserve some bytes in the strtab header for when we actually want to write its
        // header, letting the rest (potentially) spill to disk. If this cannot be reserved
        // then we have greater issues. This is a bit naughty as add in a few extra bytes
        // and assume that we can always do this, but since we reserve those bytes with
        // an allocation anyhow its pretty moot.
        let mut strtab = ArchiveBuilderData::new(spill_size + ENTRY_HEADER_LEN);

        strtab
            .write_all(&EMPTY_HEADER)
            .expect("Unable to reserve strtab header");

        Self {
            deterministic,
            generate_symbol_table,
            strtab,
            have_strtab: false,
            symbols: Vec::new(),
            symbol_names: ArchiveBuilderData::new(symbol_spill),
            entities: ArchiveBuilderData::new(spill_size),
        }
    }

    fn produce_header<W: Write>(ident: &[u8; 16], writer: &mut W, header: &Header) -> Result<()> {
        writer.write_all(ident)?;
        let Header { mtime, uid, gid, mode, size, ..  } = header;
        writeln!(writer, "{:<12}{:<6}{:<6}{:<8o}{:<10}`", mtime, uid, gid, mode, size)
    }

    fn compute_metadata_params(&mut self) -> Result<MetadataParams> {
        let num_syms = self.symbols.len() as u64;

        let mut metadata_size = GLOBAL_HEADER_LEN as u64;

        // Calculate symtab size if we are adding one
        if !self.symbols.is_empty() {
            metadata_size = metadata_size
                .saturating_add(ENTRY_HEADER_LEN as u64)
                .saturating_add(GNU_STD_SYMTAB_PTR)
                .saturating_add(GNU_STD_SYMTAB_PTR.saturating_mul(num_syms))
                .saturating_add(self.symbol_names.len()? as u64);
        }

        // Calculate strtab size if we are adding one
        if self.have_strtab {
            metadata_size = metadata_size.saturating_add(self.strtab.len()? as u64);
        }

        let total_size = metadata_size.saturating_add(self.entities.len()? as u64);
        match total_size {
            0..=GNU_STD_SYMTAB_LIMIT => Ok(MetadataParams {
                kind: SymbolTableVariant::GNU,
                name: GNU_SYMBOL_LOOKUP_TABLE_ID,
                offset: metadata_size,
                wordsize: GNU_STD_SYMTAB_PTR,
            }),
            _ => {
                if !self.symbols.is_empty() {
                    // Correct symtab size (we made it ½ the size it will be)
                    metadata_size = metadata_size
                        .saturating_add(GNU_STD_SYMTAB_PTR)
                        .saturating_add(GNU_STD_SYMTAB_PTR.saturating_mul(num_syms));
                }

                Ok(MetadataParams {
                    kind: SymbolTableVariant::GNU64BIT,
                    name: GNU_SYMBOL_64_LOOKUP_TABLE_ID,
                    offset: metadata_size,
                    wordsize: GNU_64BIT_SYMTAB_PTR,
                })
            }
        }
    }

    fn write_header(&mut self, header: &Header) -> Result<()> {
        // NOTE: GNU reserves the last char to be `/` for small names
        const GNU_ENTRY_NAME_LEN: usize = ENTRY_NAME_MAX_LEN - 1;

        let mut raw_identifier: [u8; ENTRY_NAME_MAX_LEN] = [HEADER_FILL_BYTE; ENTRY_NAME_MAX_LEN];

        if header.identifier.len() > GNU_ENTRY_NAME_LEN {
            let pos = self.strtab.position()? - ENTRY_HEADER_LEN as u64;
            self.strtab.write_all(&header.identifier)?;
            self.strtab.write_all(b"/\n")?;
            raw_identifier[0] = b"/"[0];
            itoa::write(&mut raw_identifier[1..GNU_ENTRY_NAME_LEN], pos)?;
            self.have_strtab = true;
        } else {
            let len = header.identifier.len();
            raw_identifier[0..len].copy_from_slice(&header.identifier);
            raw_identifier[len] = b"/"[0];
        }

        Self::produce_header(&raw_identifier, &mut self.entities, header)
    }
}

impl BaseBuilder for GnuBuilder {
    fn deterministic(&self) -> bool {
        self.deterministic
    }

    fn finalize(mut self) -> Result<ArchiveBuilderSections> {
        let mut builder_sections = ArchiveBuilderSections::default();

        if self.have_strtab && self.strtab.len()? % 2 != 0 {
            self.strtab.write_all(GNU_STRTAB_PAD)?;
        }

        if !self.symbols.is_empty() {
            self.symbol_names.write_all(b"\0")?;

            if self.symbol_names.len()? % 2 != 0 {
                self.symbol_names.write_all(GNU_SYMTAB_NAMES_PAD)?;
            }

            let meta_params = self.compute_metadata_params()?;

            let num_entries = self.symbols.len() as u64;
            let mut sym_ptrs = ArchiveBuilderData::new(ENTRY_HEADER_LEN + self.symbols.len());

            let symtab_str_size = self.symbol_names.len()? as u64;
            let size = num_entries.checked_mul(meta_params.wordsize)
                .and_then(|x| x.checked_add(meta_params.wordsize))
                .and_then(|x| x.checked_add(symtab_str_size))
                .ok_or_else(|| err!("Symbol table overflow"))?;

            let mut symtab_header = Header::new(meta_params.name, size);

            // ... Emulate binutils `ar` if we are not being deterministic
            if !self.deterministic {
                let mtime = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
                symtab_header.set_mtime(mtime.as_secs());
            }

            Self::produce_header(meta_params.name, &mut sym_ptrs, &symtab_header)?;

            let mut symtab_num = |n: u64| {
                match meta_params.kind {
                    SymbolTableVariant::GNU => sym_ptrs.write_all(&(n as u32).to_be_bytes()),
                    SymbolTableVariant::GNU64BIT => sym_ptrs.write_all(&n.to_be_bytes()),
                    _ => panic!("Gnu archive builder attempted to create invalid sym-table variant"),
                }
            };

            symtab_num(num_entries)?;

            // Write the offsets taking care to adjust for the final location
            self.symbols
                .iter()
                .map(|x| x + meta_params.offset)
                .try_for_each(symtab_num)?;

            builder_sections.symtab_idents = self.symbol_names;
            builder_sections.symtab_locators = sym_ptrs;
        }

        if self.have_strtab {
            // Gnu Strtab headers are awkward and only include the size
            // they also need padding if not a power of two, so apply the pad and write the
            // header as space and not as ascii 0
            let len = self.strtab.len()? - ENTRY_HEADER_LEN as u64;
            self.strtab.seek(SeekFrom::Start(0))?;
            self.strtab.write_all(GNU_NAME_TABLE_ID)?;

            self.strtab.write_all(&GNU_STRTAB_HDR_PAD)?;
            write!(&mut self.strtab, "{:<10}", len)?;
            self.strtab.write_all(HEADER_END_MARKER)?;

            builder_sections.strtab = self.strtab;
        }

        if self.entities.len()? > 0 {
            builder_sections.entities = self.entities;
        }

        builder_sections.symtab_idents.seek(SeekFrom::Start(0))?;
        builder_sections.symtab_locators.seek(SeekFrom::Start(0))?;
        builder_sections.strtab.seek(SeekFrom::Start(0))?;
        builder_sections.entities.seek(SeekFrom::Start(0))?;

        Ok(builder_sections)
    }

    fn write_data<R: Read>(&mut self, header: &Header, data: &mut R) -> Result<(u64, u64)> {
        let raw_offset = self.entities.position()?;
        self.write_header(header)?;
        let size = std::io::copy(data, &mut self.entities)?;

        if size % 2 != 0 {
            self.entities.write_all(b"\n")?;
        }

        Ok((raw_offset, size))
    }

    fn associate_symbol(&mut self, raw_offset: u64, sym: &str) -> Result<()> {
        if self.generate_symbol_table {
            self.symbol_names.write_all(sym.as_bytes())?;
            self.symbol_names.write_all(b"\0")?;
            self.symbols.push(raw_offset);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use itertools::Itertools;

    use crate::test_support::HeaderAndData;

    use proptest::{
        prelude::*,
        collection::vec as any_vec
    };

    #[test]
    fn build_gnu_archive() -> Result<()> {
        let mut builder = GnuBuilder::new(2 * 1024, false, false);
        let mut header1 = Header::new(b"foo.txt".to_vec(), 7);
        header1.set_mtime(1487552916);
        header1.set_uid(501);
        header1.set_gid(20);
        header1.set_mode(0o100644);
        builder.append(&header1, "foobar\n".as_bytes())?;

        let header2 = Header::new(b"baz.txt".to_vec(), 4);
        builder.append(&header2, "baz\n".as_bytes())?;

        let mut actual = String::new();
        builder.finish()?.read_to_string(&mut actual)?;

        let expected = "\
        !<arch>\n\
        foo.txt/        1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        baz.txt/        0           0     0     644     4         `\n\
        baz\n";
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn build_gnu_archive_with_long_filenames() -> Result<()> {
        let mut builder = GnuBuilder::new(2 * 1024, false, true);

        let mut header1 = Header::new(b"short".to_vec(), 1);
        header1.set_identifier(b"this_is_a_very_long_filename.txt".to_vec());
        header1.set_mtime(1487552916);
        header1.set_uid(501);
        header1.set_gid(20);
        header1.set_mode(0o100644);
        header1.set_size(7);
        builder.append(&header1, "foobar\n".as_bytes())?;

        let header2 = Header::new(
            b"and_this_is_another_very_long_filename.txt".to_vec(),
            4,
        );
        builder.append(&header2, "baz\n".as_bytes())?;

        let mut actual = String::new();
        builder.finish()?.read_to_string(&mut actual)?;

        let expected = "\
        !<arch>\n\
        //                                              78        `\n\
        this_is_a_very_long_filename.txt/\n\
        and_this_is_another_very_long_filename.txt/\n\
        /0              1487552916  501   20    100644  7         `\n\
        foobar\n\n\
        /34             0           0     0     644     4         `\n\
        baz\n";

        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn build_gnu_archive_with_space_in_filename() -> Result<()> {
        let mut builder = GnuBuilder::new(2 * 1024, false, true);

        let header = Header::new(b"foo bar".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes())?;
        let mut actual = String::new();
        builder.finish()?.read_to_string(&mut actual)?;

        let expected = "\
        !<arch>\n\
        foo bar/        0           0     0     644     4         `\n\
        baz\n";
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn build_gnu_archive_with_space_at_end_of_filename() -> Result<()> {
        let mut builder = GnuBuilder::new(2 * 1024, false, true);

        let header = Header::new(b"foobar         ".to_vec(), 4);
        builder.append(&header, "baz\n".as_bytes())?;
        let mut actual = String::new();
        builder.finish()?.read_to_string(&mut actual)?;

        let expected = "\
        !<arch>\n\
        foobar         /0           0     0     644     4         `\n\
        baz\n";
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn non_multiple_of_two_long_ident_in_gnu_archive() -> Result<()> {
        let mut builder = GnuBuilder::new(1 * 1024, false, true);

        let filenames = vec![
            b"rust.metadata.bin".to_vec(),
            b"compiler_builtins-78891cf83a7d3547.dummy_name.rcgu.o".to_vec(),
        ];
        for filename in filenames {
            builder
                .append(&Header::new(filename, 1), &mut (&[b'?'] as &[u8]))?;
        }

        let mut buffer = std::io::Cursor::new(Vec::new());
        std::io::copy(&mut builder.finish()?, &mut buffer)?;
        buffer.set_position(0);

        let mut archive = Archive::new(buffer);
        while let Some(entry) = archive.next_entry() {
            entry.unwrap();
        }

        Ok(())
    }

    #[test]
    fn build_gnu_archive_with_symbols() -> Result<()> {
        let mut builder = GnuBuilder::default();

        let hdr = |name| Header::new(name, 10);
        builder.append_data_with_symbols(&hdr("file1.o"), "some_data1", vec!["sym1", "sym2"])?;
        builder.append_data_with_symbols(&hdr("file2.o"), "some_data2", vec!["sym3"])?;

        // Minor - check empty symbols are noop
        builder.append_data_with_symbols(&hdr("file3_with_a_long_name.o"), "some_data3", vec![])?;
        builder.append_data(&hdr("file1.o"), "some_data4")?;

        // It is perfectly possible to have many to many symbols mappings
        // For example, ELF weak symbols have this property where in the same archive
        // one entry can weakly define say `strlen`, with another object _strongly_ defining it
        builder.append_data_with_symbols(&hdr("file5.o"), "some_data3", vec!["sym1"])?;

        let mut buffer = std::io::Cursor::new(Vec::new());
        std::io::copy(&mut builder.finish()?, &mut buffer)?;
        buffer.set_position(0);
        std::io::copy(&mut buffer, &mut std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open("/tmp/greg.a")?)?;
        buffer.set_position(0);

        let mut archive = Archive::new(buffer);
        let syms = archive.symbols()?
            .map(|x| x.name().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(syms, vec!["sym1", "sym2", "sym3", "sym1"]);

        // Check the offsets for symbols come out in order
        let offsets_in_order = archive
            .symbols()?
            .map(|x| x.offset())
            .tuple_windows()
            .all(|(x, y)| x <= y);
        assert!(offsets_in_order);

        // This is not the best API, but without GATS its harder to create an API where
        // the archive or the symbol is able to produce an iterator relating to the entities that
        // are bound to it.
        //
        // For example one better api would be
        //
        // ```
        // for symbol in archive.symbols()? {
        //  for entry in symbol.entries() ? {
        //    ...
        //  }
        // }
        // ```
        //
        // another could be
        //
        // ```
        // let some_sym_entries = archive.entries_for_symbol("some_symbol)?
        // ```
        //
        // As it stands these would require solving streaming iterators in a way where we could:
        // * partition the borrow (not yet in rust AFAICT)
        // * clone an independent reader (only really workable for unix files, which is limiting)
        // * do something with refcell (which makes for a fragile API usage at runtime)
        // * or allow a lifetime object to be borrowed "through" the various objects (needs GATS?)
        //
        // As such we can "give up" our held symbol to get the entity it points to, there is a
        // guard that is tested to make sure the symbol we are asking for an entity for actually
        // comes from a given archive.
        //
        // Suggestions welcome for a better API
        let mut assert_sym_entries = |sym, names| -> Result<()> {
            for (idx, name) in archive.entries_for_symbol(sym)?.zip(names) {
                let entry = archive.jump_to_entry(idx)?;
                assert_eq!(entry.header().identifier(), name);
            }
            Ok(())
        };

        assert_sym_entries("sym1", vec![b"file1.o", b"file5.o"])?;
        assert_sym_entries("sym2", vec![b"file1.o"])?;
        assert_sym_entries("sym3", vec![b"file2.o"])?;
        assert!(archive.entries_for_symbol("sym4")?.next().is_none());

        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn test_any_general_archive(entries in any_vec(any::<test_support::HeaderAndData>(), 0..20)) {
            let mut builder = GnuBuilder::new(64 * 1024, false, false);
            for HeaderAndData { header, data } in &entries {
                builder.append_data(&header, &data)?;
            }

            let mut raw_data = io::Cursor::new(Vec::new());
            io::copy(&mut builder.finish()?, &mut raw_data)?;
            raw_data.set_position(0);

            let mut ar = Archive::new(raw_data);
            assert_eq!(ar.count_entries()?, entries.len());

            let mut actuals = entries.iter();
            while let Some(entry) = ar.next_entry() {
                let HeaderAndData { header, data } = actuals.next().unwrap();

                let mut actual_entry = entry?;
                let actual_header = actual_entry.header();
                assert_eq!(actual_header.identifier(), header.identifier.as_ref());
                assert_eq!(actual_header.mtime(), header.mtime);
                assert_eq!(actual_header.uid(), header.uid);
                assert_eq!(actual_header.gid(), header.gid);
                assert_eq!(actual_header.mode(), header.mode);
                assert_eq!(actual_header.size(), header.size);
                assert_eq!(actual_header.size() as usize, data.len());

                let mut actual_data = io::Cursor::new(Vec::with_capacity(data.len()));
                io::copy(&mut actual_entry, &mut actual_data)?;
                let actual_data = actual_data.into_inner();
                assert_eq!(&actual_data, data);
            }
        }

        #[test]
        fn test_any_deterministic_archive(entries in any_vec(any::<test_support::HeaderAndData>(), 0..20)) {
            let mut builder = GnuBuilder::new(64 * 1024, true, false);
            for HeaderAndData { header, data } in &entries {
                builder.append_data(&header, &data)?;
            }

            let mut raw_data = io::Cursor::new(Vec::new());
            io::copy(&mut builder.finish()?, &mut raw_data)?;
            raw_data.set_position(0);

            let mut ar = Archive::new(raw_data);
            assert_eq!(ar.count_entries()?, entries.len());

            let mut actuals = entries.iter();
            while let Some(entry) = ar.next_entry() {
                let HeaderAndData { header, data } = actuals.next().unwrap();

                let mut actual_entry = entry?;
                let actual_header = actual_entry.header();
                assert_eq!(actual_header.identifier(), header.identifier.as_ref());
                assert_eq!(actual_header.mtime(), 0);
                assert_eq!(actual_header.uid(), 0);
                assert_eq!(actual_header.gid(), 0);
                assert_eq!(actual_header.mode(), 0o644);
                assert_eq!(actual_header.size(), header.size);
                assert_eq!(actual_header.size() as usize, data.len());

                let mut actual_data = io::Cursor::new(Vec::with_capacity(data.len()));
                io::copy(&mut actual_entry, &mut actual_data)?;
                let actual_data = actual_data.into_inner();
                assert_eq!(&actual_data, data);
            }
        }

        #[test]
        fn test_any_general_archive_with_syms(
            test_data in any_vec((
                any::<test_support::HeaderAndData>(),
                any_vec(r#"\PC{1, 50}"#, 0..6)
            ), 0..20)
        ) {
            let mut builder = GnuBuilder::default();
            for (HeaderAndData { header, data }, syms) in &test_data {
                let strs = syms
                    .iter()
                    .inspect(|x| println!("SYM {}", x))
                    .map(|x| x.as_ref());
                builder.append_data_with_symbols(&header, &data, strs)?;
            }

            let mut raw_data = io::Cursor::new(Vec::new());
            io::copy(&mut builder.finish()?, &mut raw_data)?;
            raw_data.set_position(0);

            let mut ar = Archive::new(raw_data);
            assert_eq!(ar.count_entries()?, test_data.len());

            let sym_tests = test_data.iter()
                .map(|(HeaderAndData { header, .. }, syms)| (header.identifier.clone(), syms))
                .flat_map(|(id, syms)| syms.iter().map(move |sym| (id.clone(), sym.clone())));

            for (id, sym) in sym_tests {
                let has_id = ar.entries_for_symbol(sym)?
                    .map(|off| ar.jump_to_entry(off).unwrap().header().identifier().to_vec())
                    .inspect(|x| println!("ID {}", String::from_utf8_lossy(x)))
                    .any(|raw| raw == id.as_ref());
                assert!(has_id);
            }
        }
    }
}
