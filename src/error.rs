//! Basic error handling macros to remove boilerplate - not for public export

/// Simple macro to produce an error in the format this crate typically produces
///
/// This is a simplification on `io::Error`
#[macro_export]
#[doc(hidden)]
macro_rules! err {
    ($fmt: expr, $($arg:tt)*) => ( std::io::Error::new(std::io::ErrorKind::InvalidInput, format!($fmt, $($arg)*)) );
    ($msg: literal) => ( Error::new(ErrorKind::InvalidInput, $msg) );
}

/// Macro to check a precondition, and if the invariant does not hold return an error
#[macro_export]
#[doc(hidden)]
macro_rules! ensure {
    ($expr: expr, $msg: literal $(,)?) => ( if !$expr { bail!($msg); } );
    ($expr: expr, $fmt: expr, $($arg:tt)*) => ( if !$expr { bail!($fmt, $($arg)*); } );
}

/// Unconditionally return an error
#[macro_export]
#[doc(hidden)]
macro_rules! bail {
    ($fmt: expr, $($arg:tt)*) => ( return Err(err!($fmt, $($arg)*)) );
    ($msg: literal) => ( return Err(err!($msg)); );
}
