# lockward-cli

Binary crate of the Lockward CLI. The program name is `lockward` (not the crate name).

```powershell
cargo run -p lockward-cli -- --help
cargo run -p lockward-cli -- --version
cargo run -p lockward-cli -- scan .
```

The analysis lives in `lockward-core`. This crate parses arguments, initializes logs on stderr, and sets the process exit code.
