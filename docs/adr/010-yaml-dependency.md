# ADR 010 — YAML-Dependency (`noyalib`)

## Kontext

Die Policy wird aus YAML gelesen. `serde_yaml` ist unmaintained, `serde_yml` ist ein abgekündigter Shim. Phase 1 nutzt dafür `noyalib`. Die Version liegt in `0.0.x`. Eine solche Abhängigkeit darf nicht unbesehen mit einem Caret-Bereich mitziehen.

## Entscheidung

`noyalib` bleibt der YAML-Parser und wird exakt auf `0.0.57` gepinnt (`version = "=0.0.57"`, Feature `compat-serde-yaml`). Aufgerufen wird nur `noyalib::from_str`. Ein Wechsel auf eine andere YAML-Crate ist kein Gewinn, solange es keine etablierte 1.x-Alternative mit demselben Serde-Vertrag gibt.

## Vendor-Review (0.0.57, crates.io, 12.10.2026)

- Lizenz: MIT OR Apache-2.0. Repository: `https://github.com/sebastienrousseau/noyalib`. Reines Rust, MSRV 1.86.
- `src/lib.rs` setzt `#![forbid(unsafe_code)]`. Im Quellbaum gibt es kein `unsafe`-Block; Treffer auf das Wort sind Kommentare (YAML-„unsafe scalar“, nicht Rust-`unsafe`).
- `build.rs` prüft nur `rustc --version` und eine Env-Variable, deklariert zwei `cfg`s und hat keine Build-Dependencies. Kein Netzwerk, kein Dateizugriff, keine Codegenerierung.
- Feature `compat-serde-yaml` schaltet `lossless-u64`. Lockward braucht davon nur das Einlesen der Policy-Datei.

Ein späteres Update ist ein eigener Review, kein stilles `cargo update`.

## Begründung

Der Parser ist bereits integriert, verbietet `unsafe` und ersetzt die archivierte YAML-Crate. Exaktes Pinning hält die `0.0.x`-Lieferkette fest, ohne die Policy-API zu wechseln.

## Alternativen

- `serde_yaml` 0.9: unmaintained.
- `serde_yml`: abgekündigter Shim auf dieselbe Linie.
- Ein anderer `0.x`-Parser nur um `0.0.x` zu vermeiden: neue Review-Fläche, kein reiferer Vertrag.
