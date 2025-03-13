/// Errors returned when serializing or deserializing sigul messages.
use std::fmt::{self, Display};

use serde::{de, ser};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Message(String),

    /// Indicates part of the field, either the key or the value, was greater than 255.
    FieldSize,

    /// The maximum number of fields allowed is 255
    FieldCount,

    /// The sigul serialization scheme doesn't support all types in serde's data model.
    UnsupportedType,

    /// Indicates there were left-over bytes when deserializing.
    TrailingBytes,

    /// Indicates more bytes were expected
    MissingBytes,
}

impl ser::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        Error::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        Error::Message(msg.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(msg) => f.write_str(msg),
            Error::FieldSize => f.write_str("field was greater than 255 bytes long"),
            Error::FieldCount => f.write_str("A struct can have no more than 255 fields"),
            Error::UnsupportedType => f.write_str("type is unsupported by the sigul format"),
            Error::TrailingBytes => f.write_str("trailing bytes during deserialization"),
            Error::MissingBytes => f.write_str("needed more bytes during deserialization"),
        }
    }
}

impl std::error::Error for Error {}
