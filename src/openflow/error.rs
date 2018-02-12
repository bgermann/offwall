use openflow::messages::*;
use std::error;
use std::fmt;
use std::io;
use std::result;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    BadRequest(OfpBadRequestCode, Vec<u8>),
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

pub type Result<T> = result::Result<T, Error>;
