use std::collections::HashMap;

use super::{Error, Result};

// While we could use serde to do de-serialization, since we have no idea what
// types any values are, I've opted to just implement a single function to
// create a HashMap.
//
// In the future, it would be nice to move Sigul to a well-supported
// serialization format. When it was initially implemented, JSON wasn't in the
// Python standard library, for example.

/// Deserialize bytes to a HashMap where all values are byte arrays.
///
/// The Sigul format doesn't include any type information and, as such,
/// can't be neatly round-trip serialized.
pub fn from_bytes(input: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    tracing::trace!(input_length = input.len(), "Parsing bytes to Sigul fields");

    let mut map = HashMap::new();
    let mut input = input.iter();
    let field_count = *input.next().unwrap_or(&0);
    tracing::trace!("Expecting to parse {} fields", field_count);
    for field_id in 0..field_count {
        let key_length = *input.next().ok_or(Error::MissingBytes)?;
        if key_length == 0 {
            return Err(Error::Message("key length was 0, which is invalid".into()));
        }
        tracing::trace!(field_id, "Expecting key to be {} bytes long", key_length);
        let mut key = vec![];
        while key.len() < key_length.into() {
            key.push(*input.next().ok_or(Error::MissingBytes)?)
        }
        let key = String::from_utf8(key)
            .map_err(|err| Error::Message(format!("Invalid UTF-8 used in key: {err:?}")))?;

        let mut value = vec![];
        let value_length = *input.next().ok_or(Error::MissingBytes)?;
        tracing::trace!(
            field_id,
            "Expecting value to be {} bytes long",
            value_length
        );
        while value.len() < value_length.into() {
            value.push(*input.next().ok_or(Error::MissingBytes)?)
        }

        map.insert(key, value);
    }

    Ok(map)
}
