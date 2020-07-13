use ar::{Builder, GnuBuilder};
use std::{
    env,
    path::PathBuf,
    io::Result
};
use assert_cmd::Command;
use pretty_assertions::assert_eq;
use indoc::indoc;

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
                println!("None GNU tool ?\n{}{}", as_str(&out.stdout), as_str(&out.stderr));
                None
            }
        },
        Err(e) => {
            println!("Command {} not found due to `{:?}` skipping test", name, e);
            None
        }
    }
}

fn fixture_path(name: &str) -> PathBuf {
    let root_dir = env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
    [&root_dir, "tests", "fixtures", name].iter().collect()
}

#[test]
fn gnu_tools_understand_archive() -> Result<()> {
    let mut gnu_ar = match command("ar") {
        Some(x) => x,
        None => return Ok(()),
    };

    let mut builder = GnuBuilder::default();

    builder.append_path_with_symbols(fixture_path("object_normal_syms.o"),
        vec!["some_function_01", "some_function_02"])?;
    builder.append_path_with_symbols(fixture_path("object_weak_syms.o"),
        vec!["some_function_02"])?;

    let mut test_file = tempfile::NamedTempFile::new()?;
    builder.finish_file(&mut test_file.as_file_mut())?;

    let gnu_out = gnu_ar.arg("tv").arg(test_file.path().as_os_str()).output()?;
    assert!(gnu_out.status.success());
    assert_eq!(indoc!(r#"
        rw-r--r-- 0/0   1328 Jan  1 00:00 1970 object_normal_syms.o
        rw-r--r-- 0/0   1232 Jan  1 00:00 1970 object_weak_syms.o
    "#), as_str(&gnu_out.stdout));

    // NM test here
    if let Some(mut gnu_nm) = command("nm") {
        let nm_out = gnu_nm.arg("--print-armap").arg(test_file.path().as_os_str()).output()?;
        assert!(nm_out.status.success());
        assert_eq!(indoc!(r#"

           Archive index:
           some_function_01 in object_normal_syms.o
           some_function_02 in object_normal_syms.o
           some_function_02 in object_weak_syms.o

           object_normal_syms.o:
           0000000000000000 T some_function_01
           0000000000000010 W some_function_02

           object_weak_syms.o:
           0000000000000000 W some_function_02
        "#), as_str(&nm_out.stdout));
    }

    Ok(())
}
