use aes_gcm::aes::cipher::InvalidLength;
use aes_gcm::Error as AgcError;
use argon2::Error as Argon2Error;
use derive_more::From;
use pqc_kyber::KyberError;

#[derive(From)]
pub enum EncryptionError {
    ArgonError(Argon2Error),
    KyberError(KyberError),
    AesLengthError(InvalidLength),
    AesError(AgcError)
}

impl EncryptionError {
    pub fn get_str(self) -> String {
        match self {
            EncryptionError::ArgonError(ref err) => format!("Argon Error {}", err.to_string()),
            EncryptionError::KyberError(ref err) => format!("Kyber Error {}", err.to_string()),
            EncryptionError::AesLengthError(ref err) => format!("Aes Error {}", err.to_string()),
            EncryptionError::AesError(ref err) => format!("Aes Error {}", err.to_string()),
        }
    }
}
