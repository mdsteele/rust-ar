use std::io;

pub(crate) fn annotate(error: io::Error, msg: &str) -> io::Error {
    let kind = error.kind();
    if let Some(inner) = error.into_inner() {
        io::Error::new(kind, format!("{}: {}", msg, inner))
    } else {
        io::Error::new(kind, msg)
    }
}
