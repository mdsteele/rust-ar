//! Builders to assist in the creation of archives
//!
//! The general intent and usage of any given archive builder is the same, the specifics on what a
//! given format or builder supports can be directly read about for the given sub-format.
use super::*;

pub mod gnu;
pub use gnu::GnuBuilder;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use std::fs::File;
use smallvec::SmallVec;

#[cfg(unix)]
fn file_and_id<P: AsRef<Path>>(path: P) -> Result<(Header, File)> {
    let identifier = path.as_ref()
        .file_name()
        .map(|name| SmallVec::from_slice(name.as_bytes()))
        .ok_or_else(|| err!("Given path doesn't have a file name"))?;

    let file = File::open(&path)?;
    let header = Header::from_meta(identifier, &file.metadata()?);
    Ok((header, file))
}

#[cfg(windows)]
fn file_and_id<P: AsRef<Path>>(path: P) -> Result<(Header, File)> {
    let identifier = path.as_ref()
        .file_name()
        .map(|name| name.encode_wide())
        .fold(Ident::new(), |(mut ident, wide)| {
            // Little-endian
            ident.push((wide & 0xFF) as u8);
            ident.push((wide >> 8) as u8);
            ident
        })
        .ok_or_else(|| err!("Given path doesn't have a file name"))?;

    let file = File::open(&path)?;
    let header = Header::from_meta(identifier, &file.metadata()?);

    Ok((header, file))
}

#[cfg(not(any(unix, windows)))]
fn file_and_id<P: AsRef<Path>>(path: P) -> Result<(Header, File)> {
    let identifier = path.as_ref()
        .file_name()
        .map(|name| str::from_utf8(&name))
        .ok_or_else(|| err!("Given path doesn't have a file name"))
        .map(|valid_name| SmallVec::from_slice(name.as_bytes()))
        .map_err(|_| err!("Non-UTF8 file name"))?;

    let file = File::open(&path)?;
    let header = Header::from_meta(identifier, &file.metadata()?);

    Ok((header, file))
}

/// An abstract archive builder
///
/// Archives and by extension their associated `Builders` come in several formats.
pub trait Builder {
    /// Add data with the given header
    fn append<R: Read>(&mut self, header: &Header, data: R) -> Result<()>;

    /// Add data with the given header
    fn append_data<D: AsRef<[u8]>>(&mut self, header: &Header, data: D) -> Result<()> {
        self.append(header, io::Cursor::new(data))
    }

    /// Add data with the given header and associated lookup symbols
    fn append_with_symbols<'a, R>(&mut self, header: &Header, data: R,
        symbols: impl IntoIterator<Item=&'a str>) -> Result<()>
        where R: Read;

    /// Add data with the given header
    fn append_data_with_symbols<'a, D: AsRef<[u8]>>(&mut self, header: &Header, data: D,
        symbols: impl IntoIterator<Item=&'a str>) -> Result<()>
    {
        self.append_with_symbols(header, io::Cursor::new(data), symbols)
    }

    /// Adds a file on the local filesystem to this archive, using the file
    /// name as its identifier.
    fn append_path<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let (header, file) = file_and_id(path)?;
        self.append(&header, file)
    }

    /// Add a file on the local filesystem to this archive, using the file name as its identifier
    /// and associating the given symbols to this file
    fn append_path_with_symbols<'a, P: AsRef<Path>>(&mut self, path: P,
        symbols: impl IntoIterator<Item=&'a str>) -> Result<()> {
        let (header, file) = file_and_id(path)?;
        self.append_with_symbols(&header, file, symbols)
    }

    /// Adds a file to this archive, with the given name as its identifier.
    fn append_file(&mut self, name: &[u8], file: &mut File) -> Result<()> {
        self.append_file_id(name.to_vec(), file)
    }

    /// Add a file to this archive, overriding the given name as its identifier.
    fn append_file_id<I: AsRef<[u8]>>(&mut self, id: I, file: &mut File) -> Result<()> {
        let metadata = file.metadata()?;
        let header = Header::from_metadata(id, &metadata);
        self.append(&header, file)
    }

    /// Add a file to this archive, overriding the given name as its identifier.
    fn append_file_id_with_symbols<'a, I: AsRef<[u8]>>(&mut self, id: I, file: &mut File,
        symbols: impl IntoIterator<Item=&'a str>) -> Result<()> {
        let metadata = file.metadata()?;
        let header = Header::from_metadata(id, &metadata);
        self.append_with_symbols(&header, file, symbols)
    }

    /// Return the result of the builder as a readable I/O object
    fn finish(self) -> Result<Box<dyn Read>>;

    /// Specialised return to allow builders to more efficiently render the archive to a file
    ///
    /// This function is a potential optimisation designed to allow for builders that might have
    /// produced large or disk spilled files to efficiently render the archive to an output file,
    /// this is recommended over `finish` if you want to render the builder directly to a file.
    fn finish_file(self, file: &mut File) -> Result<()>;

    /// Specialised return to allow builders to more efficiently render the archive to a path
    ///
    /// This is similar to `finish_file` but takes a plain path instead of a file object
    fn finish_path<P: AsRef<std::path::Path>>(self, path: P) -> Result<File>;
}

/// Archives are a bit annoying to actually build
///
/// Without the symbol table the archive is _practically_ useless for most linkers, with most
/// linkers choosing to ignore the archive until `ranlib` (or similar) has been run on the archive.
///
/// There are a myriad of formats for an archive, which are explained in the following:
/// * Linkers and loaders (John R Levine) - https://linker.iecc.com/
/// * BSD `ar(5)` - https://www.freebsd.org/cgi/man.cgi?query=ar&sektion=5
/// * Solaris `ar.h(3HEAD)` - https://docs.oracle.com/cd/E36784_01/html/E36873/ar.h-3head.html
///
/// The biggest challenge is the symbol and string tables must be present at the start of the
/// archive but the symbol table has pointers pointing into the rest of the file.
///
/// These two tables _must_ be the first members of an archive otherwise many linkers will not be
/// happy with the resulting file.
///
/// Archives are not expected to have gaps in them (and again some linkers object to this) and so
/// its not possible to just make a file with a large pad between the special members and the rest
/// of the resulting data.
///
/// Naturally the source code of LLVM and or binutils explains the format somewhat, but can be a
/// bit obstrfucatory.
///
/// This mod encapsulates the generic parts of generating archives at scale but is aimed at hiding
/// the implementation details from end users.
pub(crate) mod private {
    use super::*;

    /// This enum allows for the generation of these archives in the relevant components, but spilled
    /// to disk if any part of the end archive becomes larger than an end user configurable limit.
    pub enum ArchiveBuilderData {
        Inline(io::Cursor<Vec<u8>>),
        Spilled(std::fs::File),
        Empty,
    }

    impl Default for ArchiveBuilderData {
        fn default() -> Self {
            Self::Empty
        }
    }

    impl ArchiveBuilderData {
        /// Create a new buffer that spills to anonymous tempory files when it reaches `size` limit
        pub(in super) fn new(size: usize) -> Self {
            Self::Inline(io::Cursor::new(Vec::with_capacity(size)))
        }

        /// Get the current position in the buffer for working out offsets
        pub(in super) fn position(&mut self) -> Result<u64> {
            match self {
                Self::Spilled(x) => x.seek(SeekFrom::Current(0)),
                Self::Inline(x) => x.seek(SeekFrom::Current(0)),
                Self::Empty => Ok(0),
            }
        }

        /// Return the length in bytes of this data
        pub(in super) fn len(&mut self) -> Result<u64> {
            match self {
                Self::Spilled(x) => x.metadata().map(|x| x.len() as u64),
                Self::Inline(x) => Ok(x.get_ref().len() as u64),
                Self::Empty => Ok(0),
            }
        }
    }

    impl Write for ArchiveBuilderData {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            match self {
                Self::Spilled(x) => x.write(buf),
                Self::Inline(inline) => {
                    if inline.get_ref().len() + buf.len() > inline.get_ref().capacity() {
                        // We spilled out of in memory buffers to disk
                        inline.set_position(0);
                        let mut file = tempfile::tempfile()?;

                        std::io::copy(inline, &mut file)?;

                        let res = file.write(buf);
                        if res.is_ok() {
                            *self = Self::Spilled(file);
                        }

                        res
                    } else {
                        inline.write(buf)
                    }
                },
                Self::Empty => Ok(0),
            }
        }

        fn flush(&mut self) -> Result<()> {
            match self {
                Self::Spilled(x) => x.flush(),
                Self::Inline(_) | Self::Empty => Ok(()),
            }
        }
    }

    impl Read for ArchiveBuilderData {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            match self {
                Self::Spilled(x) => x.read(buf),
                Self::Inline(x) => x.read(buf),
                Self::Empty => Ok(0),
            }
        }
    }

    impl Seek for ArchiveBuilderData {
        fn seek(&mut self, seek: SeekFrom) -> Result<u64> {
            match self {
                Self::Spilled(x) => x.seek(seek),
                Self::Inline(x) => x.seek(seek),
                Self::Empty => Ok(0),
            }
        }
    }

    /// Final produced sections of an archive from one of the builder implementations
    ///
    /// This takes some care to allow for different archive types to implement the common sections
    /// how they choose, while still allowing for parts of the archive to spill to disk (in cases of
    /// large archives).
    ///
    /// Symbols may not be present if the end user is not generating a symbol table (sometimes done
    /// for archive generation in a scatter/gather approach) or if no symbols are associated with
    /// anything in the archive. Note however that most toolchains and linkers will _dislike_ archives
    /// that lack symbol tables and will typically state that such artifacts are unrecognised formats.
    ///
    /// The end user can _manually_ run `ranlib` on such archives to complete them (or do some other
    /// processing with such slightly none typical archives).
    ///
    /// "Debian" archives never contain symbol tables.
    ///
    /// The string table might not exist if the archive format has a different strategy for extended
    /// names (BSD) or lacks any extended names in generation.
    #[derive(Default)]
    pub struct ArchiveBuilderSections {
        /// The locator table for any symbols encoded in the archive, this is format specific between
        /// GNU and BSD archives.
        pub(crate) symtab_locators: ArchiveBuilderData,

        /// The string idents encoded as per the builder format for the given symbols.
        /// These may spill to disk if they get larger than a percentage of the end users spill factor
        pub(crate) symtab_idents: ArchiveBuilderData,

        /// Extended string names if present and supported by the format
        /// These may spill to disk if they get larger than a percentage of the end users spill factor
        pub(crate) strtab: ArchiveBuilderData,

        /// The core entities for this archive format. Note that this data is still format specific
        /// These may spill to disk if they get larger than a percentage of the end users spill factor
        pub(crate) entities: ArchiveBuilderData,
    }

    /// Since archives are pretty similar outside of the strtab and symtab we make a generic builder
    /// that covers the smaller parts of the I/O while leaving the specifics up to each format.
    ///
    /// This builder is not exposed outside of the crate and is not of interest to end users but is
    /// rather an implementation details
    pub trait BaseBuilder {
        fn deterministic(&self) -> bool;

        fn write_data<R: Read>(&mut self, header: &Header, data: &mut R) -> Result<(u64, u64)>;

        fn associate_symbol(&mut self, raw_offset: u64, sym: &str) -> Result<()>;

        fn write_entity<'a, R: Read>(&mut self, header: &Header, mut data: R,
            symbols: impl IntoIterator<Item=&'a str>) -> Result<u64>
        {
            header.validate()?;
            let (raw_offset, actual_size) = if self.deterministic() {
                let header = header.make_deterministic();
                self.write_data(&header, &mut data)?
            } else {
                self.write_data(header, &mut data)?
            };

            ensure!(actual_size == header.size(),
                "Wrong file size (header.size() = {}, actual size was {})", header.size(), actual_size);

            symbols.into_iter()
                .try_for_each(|sym| self.associate_symbol(raw_offset, sym.as_ref()))?;

            Ok(actual_size)
        }

        fn write_archive_data_file(input: &mut ArchiveBuilderData, file: &mut File) -> Result<u64> {
            match input {
                ArchiveBuilderData::Empty => Ok(0),
                ArchiveBuilderData::Inline(data) => std::io::copy(data, file),
                ArchiveBuilderData::Spilled(src_file) => if cfg!(unix) {
                    // On unix try an optimised `splice` styled copy
                    use std::os::unix::io::AsRawFd;
                    use nix::{
                        Error as NixErr,
                        fcntl::copy_file_range
                    };

                    let src = src_file.as_raw_fd();
                    let dst = file.as_raw_fd();
                    let len = src_file.metadata()?.len() as usize;

                    match copy_file_range(src, None, dst, None, len) {
                        Ok(bytes) => Ok(bytes as u64),
                        Err(NixErr::Sys(errno)) => Err(Error::from_raw_os_error(errno as i32)),
                        Err(NixErr::InvalidPath) => bail!("Invalid path"),
                        Err(NixErr::InvalidUtf8) => bail!("Invalid utf8 for path"),
                        // If we dont get `copy_file_range` fallback to copy
                        Err(NixErr::UnsupportedOperation) => io::copy(src_file, file),
                    }
                } else {
                    std::io::copy(src_file, file)
                }
            }
        }

        fn finalize(self) -> Result<ArchiveBuilderSections>;
    }

    impl <T: BaseBuilder> Builder for T {
        fn append<R: Read>(&mut self, header: &Header, data: R) -> Result<()> {
            self.write_entity(header, data, std::iter::empty())?;
            Ok(())
        }

        fn append_with_symbols<'a, R>(&mut self, header: &Header, data: R,
            symbols: impl IntoIterator<Item=&'a str>) -> Result<()>
            where R: Read
        {
            self.write_entity(header, data, symbols)?;
            Ok(())
        }

        fn finish(self) -> Result<Box<dyn Read>> {
            let sections = self.finalize()?;

            let output = io::Cursor::new(GLOBAL_HEADER)
                .chain(sections.symtab_locators)
                .chain(sections.symtab_idents)
                .chain(sections.strtab)
                .chain(sections.entities);

            Ok(Box::new(output))
        }

        fn finish_path<P: AsRef<std::path::Path>>(self, path: P) -> Result<File> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(path)?;

            self.finish_file(&mut file)?;

            Ok(file)
        }

        fn finish_file(self, file: &mut File) -> Result<()> {
            file.write_all(GLOBAL_HEADER)?;

            let mut sections = self.finalize()?;
            Self::write_archive_data_file(&mut sections.symtab_locators, file)?;
            Self::write_archive_data_file(&mut sections.symtab_idents, file)?;
            Self::write_archive_data_file(&mut sections.strtab, file)?;
            Self::write_archive_data_file(&mut sections.entities, file)?;

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /*
    #[test]
    fn absurd_header_values() -> Result<()> {
        let mut builder = GnuBuilder::new(64 * 1024, false, false);
        let mut header = Header::new(&[0], 0);
        header.set_mode(16777216);
        builder.append_data(&header, vec![])?;

        let mut buffer = io::Cursor::new(Vec::new());
        io::copy(&mut builder.finish()?, &mut buffer)?;
        buffer.set_position(0);

        let mut archive = Archive::new(buffer);
        while let Some(entry) = archive.next_entry() {
            entry.unwrap();
        }

        Ok(())
    }
    */
}
