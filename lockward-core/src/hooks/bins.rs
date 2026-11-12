// SPDX-License-Identifier: AGPL-3.0-only

//! Publishers allowed to declare a trusted build command's `bin` name.
//!
//! The command names are the bare names in `TRUSTED_COMMANDS` that npm can
//! link. `@mapbox/node-pre-gyp` is not a command name: its published `bin`
//! is `node-pre-gyp`. Publisher lists were read from each package's latest
//! `package.json` on the npm registry on 2026-11-12, not inferred from the
//! command spelling.

use crate::ingest::Package;
use std::collections::BTreeSet;

/// Trusted command, then the package names allowed to publish that bin.
///
/// Both columns are strictly sorted. `binary_search` depends on that.
const TRUSTED_BIN_PUBLISHERS: &[(&str, &[&str])] = &[
    ("cmake-js", &["cmake-js"]),
    ("husky", &["husky"]),
    // The package `napi-build` is not on the registry (HTTP 404).
    // `@napi-rs/cli` 3.10.12 publishes `napi` and `napi-raw`.
    // `node-gyp-build` 4.8.4 publishes `node-gyp-build`,
    // `node-gyp-build-test`, and `node-gyp-build-optional`.
    // `@ironblood/napi-cli-build` 3.4.1-alpha.1 is the package whose `bin`
    // map names `napi-build`.
    ("napi-build", &["@ironblood/napi-cli-build"]),
    ("node-gyp", &["node-gyp"]),
    ("node-gyp-build", &["node-gyp-build"]),
    // `node-pre-gyp` 0.17.0 and `@mapbox/node-pre-gyp` 2.0.3 both publish
    // the command `node-pre-gyp`.
    ("node-pre-gyp", &["@mapbox/node-pre-gyp", "node-pre-gyp"]),
    ("patch-package", &["patch-package"]),
    ("prebuild-install", &["prebuild-install"]),
    ("prebuildify", &["prebuildify"]),
];

/// One package declared a trusted bin name it does not publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinShadow {
    /// Lockfile package name.
    pub package_name: String,
    /// Locked version.
    pub package_version: String,
    /// Lockfile path.
    pub package_path: String,
    /// Bin command that collides with a trusted build tool.
    pub command: String,
}

/// Packages whose `bin` claims a trusted command they are not allowed to publish.
#[must_use]
pub fn bin_shadows(packages: &[Package]) -> Vec<BinShadow> {
    let mut found = Vec::new();
    for package in packages {
        for command in package.bins.keys() {
            let Some(publishers) = publishers_for(command) else {
                continue;
            };
            if publishers.binary_search(&package.name.as_str()).is_ok() {
                continue;
            }
            found.push(BinShadow {
                package_name: package.name.clone(),
                package_version: package.version.clone(),
                package_path: package.path.clone(),
                command: command.clone(),
            });
        }
    }
    found.sort_by(|left, right| {
        left.package_path
            .cmp(&right.package_path)
            .then(left.command.cmp(&right.command))
    });
    found
}

/// Trusted command names that a non-publisher declared in this lockfile.
#[must_use]
pub fn shadowed_commands(packages: &[Package]) -> BTreeSet<String> {
    bin_shadows(packages)
        .into_iter()
        .map(|shadow| shadow.command)
        .collect()
}

/// Publisher names for a trusted command, when it is in the table.
#[must_use]
pub fn publishers_for(command: &str) -> Option<&'static [&'static str]> {
    TRUSTED_BIN_PUBLISHERS
        .binary_search_by_key(&command, |row| row.0)
        .ok()
        .map(|index| TRUSTED_BIN_PUBLISHERS[index].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_table_is_strictly_sorted_and_covers_bare_trusted_commands() {
        let commands: Vec<_> = TRUSTED_BIN_PUBLISHERS.iter().map(|row| row.0).collect();
        let mut sorted = commands.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(commands, sorted);
        for (_, publishers) in TRUSTED_BIN_PUBLISHERS {
            let names = publishers.to_vec();
            let mut sorted = names.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(names, sorted, "{publishers:?}");
        }
        for command in super::super::command::trusted_command_names() {
            if command.contains('/') {
                continue;
            }
            assert!(
                publishers_for(command).is_some(),
                "{command} has no publisher row"
            );
        }
    }
}
