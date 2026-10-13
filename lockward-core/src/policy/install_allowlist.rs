// SPDX-License-Identifier: AGPL-3.0-only

//! Curated names of packages whose install scripts are a normal build step.
//!
//! Matching is exact. A typosquat such as `esbudld` or `puppeteer-core` is not
//! covered by `esbuild` or `puppeteer`. The list is a name anchor only; it is
//! not a registry identity or an integrity hash.

/// One curated package.
pub struct InstallAllow {
    /// npm package name.
    pub name: &'static str,
    /// The package is a known binary or browser downloader.
    ///
    /// For these names, a plain network fetch in the install hook (`LW-H003`)
    /// is treated as the expected download. A pipe into a shell (`LW-H004`)
    /// is not covered.
    pub binary_fetch: bool,
}

/// Packages shipped with the default policy.
///
/// Sorted by name. `binary_fetch` marks downloaders whose install hook is
/// expected to talk to the network.
pub static INSTALL_ALLOWLIST: &[InstallAllow] = &[
    InstallAllow {
        name: "@grpc/grpc-js",
        binary_fetch: false,
    },
    InstallAllow {
        name: "@mapbox/node-pre-gyp",
        binary_fetch: false,
    },
    InstallAllow {
        name: "@swc/core",
        binary_fetch: false,
    },
    InstallAllow {
        name: "bcrypt",
        binary_fetch: false,
    },
    InstallAllow {
        name: "better-sqlite3",
        binary_fetch: false,
    },
    InstallAllow {
        name: "canvas",
        binary_fetch: false,
    },
    InstallAllow {
        name: "core-js",
        binary_fetch: false,
    },
    InstallAllow {
        name: "cypress",
        binary_fetch: true,
    },
    InstallAllow {
        name: "electron",
        binary_fetch: true,
    },
    InstallAllow {
        name: "esbuild",
        binary_fetch: false,
    },
    InstallAllow {
        name: "fsevents",
        binary_fetch: false,
    },
    InstallAllow {
        name: "grpc",
        binary_fetch: false,
    },
    InstallAllow {
        name: "node-gyp",
        binary_fetch: false,
    },
    InstallAllow {
        name: "node-pre-gyp",
        binary_fetch: false,
    },
    InstallAllow {
        name: "node-sass",
        binary_fetch: false,
    },
    InstallAllow {
        name: "playwright",
        binary_fetch: true,
    },
    InstallAllow {
        name: "prebuild-install",
        binary_fetch: false,
    },
    InstallAllow {
        name: "puppeteer",
        binary_fetch: true,
    },
    InstallAllow {
        name: "re2",
        binary_fetch: false,
    },
    InstallAllow {
        name: "sass",
        binary_fetch: false,
    },
    InstallAllow {
        name: "sharp",
        binary_fetch: false,
    },
    InstallAllow {
        name: "sodium-native",
        binary_fetch: false,
    },
    InstallAllow {
        name: "sqlite3",
        binary_fetch: false,
    },
];

/// Exact curated name, ignoring user-added policy entries.
#[must_use]
pub fn curated(name: &str) -> Option<&'static InstallAllow> {
    INSTALL_ALLOWLIST.iter().find(|entry| entry.name == name)
}

/// The name is a curated binary downloader.
#[must_use]
pub fn binary_fetch(name: &str) -> bool {
    curated(name).is_some_and(|entry| entry.binary_fetch)
}
