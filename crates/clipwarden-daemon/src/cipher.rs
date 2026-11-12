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

//! The encrypted memory of the clipboard content.
//!
//! While ClipWarden protects the clipboard it keeps the original text in
//! memory: it is needed when the user pastes the content into a trusted
//! application. That text is the secret, so it is stored encrypted with
//! AES-256-GCM under a key that is generated when the service starts and
//! that never leaves the process.
//!
//! The content is wiped as soon as the clipboard changes, so it is never
//! kept around longer than necessary. The encryption is a second line of
//! defence: it makes a memory dump of the service useless without the key
//! of the running process.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

/// Length of the key.
const KEY_LENGTH: usize = 32;

/// Length of the nonce.
const NONCE_LENGTH: usize = 12;

/// An encrypted text.
#[derive(Debug, Default)]
pub struct Sealed {
    /// The encrypted bytes.
    bytes: Vec<u8>,
    /// The nonce that was used.
    nonce: Vec<u8>,
}

/// The cipher of the process.
///
/// The key is generated once, when the service starts.
pub struct Cipher {
    cipher: Aes256Gcm,
}

impl Default for Cipher {
    /// Creates the cipher with a fresh random key.
    fn default() -> Self {
        Self::new()
    }
}

impl Cipher {
    /// Creates the cipher with a fresh random key.
    pub fn new() -> Self {
        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
        getrandom::fill(key.as_mut()).expect("the random number generator must work");
        let cipher = Aes256Gcm::new((&*key).into());
        Self { cipher }
    }

    /// Encrypts a text.
    pub fn seal(&self, text: &str) -> Sealed {
        let mut nonce_bytes = Zeroizing::new([0u8; NONCE_LENGTH]);
        getrandom::fill(nonce_bytes.as_mut()).expect("the random number generator must work");
        let nonce = Nonce::from_slice(&nonce_bytes[..]);
        let bytes = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: text.as_bytes(),
                    aad: b"clipwarden-vault",
                },
            )
            .unwrap_or_default();
        Sealed {
            bytes,
            nonce: nonce_bytes.to_vec(),
        }
    }

    /// Decrypts a text.
    pub fn open(&self, sealed: &Sealed) -> Option<String> {
        if sealed.bytes.is_empty() {
            return None;
        }
        let nonce = Nonce::from_slice(&sealed.nonce);
        let plain = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed.bytes,
                    aad: b"clipwarden-vault",
                },
            )
            .ok()?;
        String::from_utf8(plain).ok()
    }
}

impl Drop for Sealed {
    fn drop(&mut self) {
        // The encrypted bytes are not a secret, but the buffer is wiped
        // anyway, so that nothing is left behind.
        self.bytes.iter_mut().for_each(|byte| *byte = 0);
        self.nonce.iter_mut().for_each(|byte| *byte = 0);
    }
}
