
//! An implementation of `Error` type.

/// The error type for I/O operations with storage.
#[derive(Fail, Debug, Clone)]
#[fail(display = "{}", message)]
pub struct Error {
    message: String,
}

impl Error {
    /// Creates a new storage error with an information message about the reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::Error;
    ///
    /// let error = Error::new("Oh no!");
    /// ```
    pub fn new<T: Into<String>>(message: T) -> Error {
        Error {
            message: message.into(),
        }
    }
}