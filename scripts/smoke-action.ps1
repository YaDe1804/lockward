# Local smoke test for the Lockward composite action.
# Does not open a pull request and does not talk to GitHub.

$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$action = Get-Content -Raw ".github\actions\lockward\action.yml"
$required = @(
    "using: composite",
    "comment.md",
    "summary.md",
    "exit-code",
    "lockward-bin",
    "mode"
)
foreach ($needle in $required) {
    if ($action -notlike "*$needle*") {
        throw "action.yml is missing '$needle'"
    }
}

$example = Get-Content -Raw ".github\workflows\example-lockward.yml"
if ($example -notlike "*uses: ./.github/actions/lockward*") {
    throw "example workflow does not call the local action"
}

cargo run -q -p lockward-cli -- scan "lockward-core\tests\fixtures\report\mini" --offline --format summary --scanned-at "2026-10-12T00:00:00Z"
if ($LASTEXITCODE -ne 1) {
    throw "expected gate exit 1 for the mini fixture, got $LASTEXITCODE"
}

Write-Output "smoke ok: action.yml, example workflow, mini fixture exit 1"
