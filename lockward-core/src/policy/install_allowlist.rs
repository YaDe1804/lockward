// SPDX-License-Identifier: AGPL-3.0-only

//! Known binary and browser downloaders.
//!
//! These packages legitimately contact the network during install. The list is
//! a finite category, not a place for packages that failed a corpus run.
//! Native build tools are recognized by command name, not by this list.

/// Package names whose install-time download is expected.
///
/// `chromedriver`, `geckodriver`, `puppeteer`, `playwright`, `cypress` and
/// `electron` fetch a browser or driver. `node-sass` and `sass-embedded` fetch
/// a native stylesheet binary. `*-core` packages are the same fetchers without
/// the convenience wrapper.
pub static KNOWN_DOWNLOADERS: &[&str] = &[
    "chromedriver",
    "cypress",
    "electron",
    "geckodriver",
    "node-sass",
    "playwright",
    "playwright-core",
    "puppeteer",
    "puppeteer-core",
    "sass-embedded",
];

/// The package is a known browser or binary fetcher.
#[must_use]
pub fn known_downloader(name: &str) -> bool {
    KNOWN_DOWNLOADERS.binary_search(&name).is_ok()
}
