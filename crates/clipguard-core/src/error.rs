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

//! Error types for the ClipGuard security engine.

use std::path::PathBuf;

/// Errors produced by the core engine.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A user-supplied regular expression failed to compile.
    #[error("invalid pattern for rule `{rule}`: {source}")]
    InvalidPattern {
        /// Name of the rule the pattern belongs to.
        rule: String,
        /// The underlying regex compilation error.
        #[source]
        source: regex::Error,
    },

    /// The configuration file could not be parsed.
    #[error("failed to parse configuration: {0}")]
    ConfigParse(#[from] toml::de::Error),

    /// The configuration file could not be serialised.
    #[error("failed to serialise configuration: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),

    /// The configuration file could not be read or written.
    #[error("failed to access configuration file `{path}`: {source}")]
    Io {
        /// Path that was being accessed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configuration failed a semantic validation check.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Convenience alias for core engine results.
pub type Result<T> = std::result::Result<T, CoreError>;
