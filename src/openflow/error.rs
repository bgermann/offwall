/*!
The shared errors across the `offwall::openflow` module.
*/

use openflow::messages::OfpBadRequestCode;
use std::error;
use std::fmt;
use std::io;
use std::result;

/// Represents all errors that can
/// occur while handling OpenFlow nessages
#[derive(Debug)]
pub enum Error {
    /// An I/O error
    Io(io::Error),
    /// An OpenFlow Bad Request error
    BadRequest(OfpBadRequestCode, Vec<u8>),
    /// An OpenFlow Hello Failed error
    HelloFailed,
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Deserialization error"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// The Result for operations that can fail with an OpenFlow error
pub type Result<T> = result::Result<T, Error>;
