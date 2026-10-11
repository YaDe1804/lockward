# Lockward GitHub Action

Composite Action für den statischen npm-Scan. Sie führt `lockward scan` aus, hängt die Kurzfassung an die GitHub Step Summary und kann den PR-Kommentar aus `comment.md` posten. Der Exit-Code der Action ist der Gate-Code: `0` OK, `1` Warnung, `2` Fail.

Die Action erwartet eine gebaute Binary. Sie lädt kein Release herunter, solange noch keines veröffentlicht ist.

## Beispiel

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  - uses: dtolnay/rust-toolchain@stable
  - run: cargo build --release -p lockward-cli
  - uses: ./.github/actions/lockward
    with:
      path: .
      mode: warn
      lockward-bin: target/release/lockward
```

`comment: "false"` unterdrückt den PR-Kommentar. `offline: "true"` liest nur den Advisory-Cache.

## Marketplace

`action.yml` ist das Manifest (Name, Beschreibung, Inputs, Outputs, Branding). Die Veröffentlichung im Marketplace braucht ein öffentliches Repo und einen Tag. Das ist ein manueller Schritt und läuft nicht in diesem Nachtlauf.
