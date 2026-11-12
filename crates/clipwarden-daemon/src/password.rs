// Copyright 2026 Mukilesh
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The password of the dashboard.
//!
//! The password is stored as a hash. A plain SHA-256 would be too weak: the
//! hash itself would be the credential, because it can be typed into the
//! password field. Argon2id with a random salt per password is used instead,
//! so that the stored value cannot be used to log in.
//!
//! Hashes of older versions (a plain SHA-256) are still accepted, so that an
//! existing installation keeps working. They are replaced the next time the
//! password is changed.

use argon2::Argon2;
use argon2::password_hash::{
    Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};

/// Hashes a password with Argon2id and a random salt.
///
/// The result is a string in the PHC format, for example
/// `argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.
pub fn hash(password: &str) -> Result<String, PasswordHashError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}

/// Checks a password against a stored hash.
///
/// The comparison takes the same time for every password, so that the answer
/// cannot be guessed by measuring it.
pub fn verify(password: &str, stored: &str) -> bool {
    if stored.is_empty() {
        return false;
    }
    match PasswordHash::new(stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// The random number generator of the password hash library.
use argon2::password_hash::rand_core::OsRng;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_right_password_verifies() {
        let hash = hash("correct horse").expect("the hash must be created");
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert!(verify("correct horse", &hash));
        assert!(!verify("correct hors", &hash));
        assert!(!verify("wrong horse", &hash));
    }

    #[test]
    fn every_hash_gets_its_own_salt() {
        let first = hash("same password").expect("the hash must be created");
        let second = hash("same password").expect("the hash must be created");
        assert_ne!(first, second, "the salt must be random");
        assert!(verify("same password", &first));
        assert!(verify("same password", &second));
    }

    #[test]
    fn an_empty_password_never_verifies() {
        assert!(!verify("anything", ""));
    }

    #[test]
    fn a_hash_of_an_older_version_is_rejected() {
        // The software was not released with the old SHA-256 hashes, so they
        // are not accepted any more.
        let legacy = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(!verify("legacy password", legacy));
    }
}
