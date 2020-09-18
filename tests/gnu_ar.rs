use ar::{Archive, Header, GnuBuilder, GnuSymbolTableFormat};
use assert_cmd::Command;
use indoc::indoc;
use pretty_assertions::assert_eq;
use std::{
    collections::BTreeMap,
    error::Error,
    fs::File,
    io::Cursor,
    path::PathBuf
};
use itertools::Itertools;

#[inline]
fn as_str(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).to_string()
}

/// Dumb naive function that returns the command if it exists and can pass some basic checks
fn command(name: &str) -> Option<Command> {
    match Command::new(name).arg("--version").output() {
        Ok(out) => {
            if out.status.success() && as_str(&out.stdout).contains("GNU") {
                let mut command = Command::new(name);
                command.env("TZ", "UTC");
                Some(command)
            } else {
                println!(
                    "Non-GNU tool ?\nstdout:\n{}\nstderr:\n{}",
                    as_str(&out.stdout),
                    as_str(&out.stderr)
                );
                None
            }
        }
        Err(e) => {
            println!(
                "Command {} not found due to `{:?}` skipping test",
                name, e
            );
            None
        }
    }
}

fn fixture_path(name: &str) -> PathBuf {
    let root_dir = env!("CARGO_MANIFEST_DIR");
    [&root_dir, "tests", "fixtures", name].iter().collect()
}

macro_rules! bin {
    ($val: literal) => {
        $val.as_bytes().to_vec()
    };
}

macro_rules! bin_vec {
    ($($values:literal),*) => ( vec![$(bin!($values),)*] )
}

fn build_ar() -> Result<(tempfile::TempDir, PathBuf), Box<dyn Error>> {
    let target = platforms::guess_current()
        .ok_or_else(|| "Cannot work out the target platform")?;

    tempfile::tempdir()
        .map_err(|e| e.into())
        .and_then(|dir| {
            cc::Build::new()
                .target(target.target_triple)
                .opt_level(2)
                .host(target.target_triple)
                .out_dir(&dir)
                .file(fixture_path("object_normal_syms.c"))
                .file(fixture_path("object_weak_syms.c"))
                .include(fixture_path(""))
                .try_compile("libnative.a")
                .map_err(|e| e.into())
                .and(Ok(dir))
        })
        .map(|dir| {
            let native = dir.as_ref().join("libnative.a");
            (dir, native)
        })
}

#[test]
fn gnu_tools_understand_archive() -> Result<(), Box<dyn Error>> {
    let mut gnu_ar = match command("ar") {
        Some(x) => x,
        None => return Ok(()),
    };

    let (_tmp_dir, native_ar) = build_ar()?;
    let mut reader = Archive::new(File::open(native_ar)?);

    let mut entries = BTreeMap::new();
    while let Some(next) = reader.next_entry() {
        let mut next = next?;
        let header = next.header();
        let ident = header.identifier().to_vec();
        let mut data = Cursor::new(Vec::with_capacity(header.size() as usize));
        std::io::copy(&mut next, &mut data)?;
        data.set_position(0);
        entries.insert(ident, data);
    }

    let idents = bin_vec!["object_normal_syms.o", "object_weak_syms.o"];
    let mut syms = BTreeMap::new();
    syms.insert(bin!("object_weak_syms.o"), bin_vec!["some_function_02"]);
    syms.insert(
        bin!("object_normal_syms.o"),
        bin_vec!["some_function_01", "some_function_02"],
    );

    let mut builder = GnuBuilder::new_with_symbol_table(
        tempfile::NamedTempFile::new()?,
        true,
        idents,
        GnuSymbolTableFormat::Size32,
        syms,
    )?;

    for (ident, data) in &mut entries {
        builder.append(&Header::new(ident.to_vec(), data.get_ref().len() as u64), data)?;
    }

    let test_file = builder.into_inner()?;

    let gnu_out = gnu_ar
        .arg("tv")
        .arg(test_file.path().as_os_str())
        .output()?;

    assert!(gnu_out.status.success());
    let expected = entries.iter()
        .map(|(id, data)| (String::from_utf8_lossy(id), data.get_ref().len()))
        .map(|(id, size)| format!(r#"rw-r--r-- 0/0   {} Jan  1 00:00 1970 {}"#, size, id))
        .join("\n");

    assert_eq!(expected, as_str(&gnu_out.stdout).trim());

    // NM test here
    if let Some(mut gnu_nm) = command("nm") {
        let nm_out = gnu_nm
            .arg("--print-armap")
            .arg(test_file.path().as_os_str())
            .output()?;

        assert!(nm_out.status.success());
        assert_eq!(indoc!(r#"

               Archive index:
               some_function_01 in object_normal_syms.o
               some_function_02 in object_normal_syms.o
               some_function_02 in object_weak_syms.o

               object_normal_syms.o:
               0000000000000000 T some_function_01
               0000000000000000 W some_function_02

               object_weak_syms.o:
               0000000000000000 W some_function_02
            "#),
            as_str(&nm_out.stdout)
        );
    }

    Ok(())
}
