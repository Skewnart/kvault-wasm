use std::string::FromUtf8Error;
use derive_more::From;

#[derive(From)]
pub enum StringError {
    Utf8Error(FromUtf8Error)
}

impl StringError {
    pub fn get_str(self) -> String {
        match self {
            StringError::Utf8Error(ref err) => format!("UTF8 Error {}", err.to_string())
        }
    }
}
