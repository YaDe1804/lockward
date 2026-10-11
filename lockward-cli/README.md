# lockward-cli

Binary-Crate der Lockward-CLI. Der Programmname ist `lockward` (nicht der Crate-Name).

```powershell
cargo run -p lockward-cli -- --help
cargo run -p lockward-cli -- --version
cargo run -p lockward-cli -- scan .
```

Analyse steckt in `lockward-core`. Diese Crate parst Argumente, initialisiert Logs auf stderr und setzt den Prozess-Exit-Code.
