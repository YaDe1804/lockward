// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned, rule-based heuristic engine over install-hook text.
//!
//! Rules are static. They classify strings already loaded by [`crate::hooks`].
//! They never execute those strings.

use crate::hooks::HookFinding;
use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

/// Rule-set version written into reports.
pub const ENGINE_VERSION: &str = "heuristics-v1";

const MAX_EVIDENCE: usize = 120;

/// A published rule. Patterns live next to the compiled engine, not in this catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuleInfo {
    /// Stable id, for example `LW-H001`.
    pub id: &'static str,
    /// What the rule is looking for.
    pub description: &'static str,
    /// Score weight before the heuristic cap.
    pub weight: u32,
    /// Inert example that should match.
    pub example: &'static str,
}

/// One rule hit on one hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeuristicFinding {
    /// Rule id.
    pub rule_id: &'static str,
    /// Rule description.
    pub description: &'static str,
    /// Rule weight.
    pub weight: u32,
    /// Package name.
    pub package_name: String,
    /// Package version.
    pub package_version: String,
    /// Lockfile path.
    pub package_path: String,
    /// Hook name.
    pub hook: String,
    /// Short excerpt of the match.
    pub evidence: String,
    /// German sentence explaining why this is risky.
    pub explanation: String,
}

struct CompiledRule {
    info: RuleInfo,
    reason: &'static str,
    pattern: Regex,
}

/// Catalog of heuristics v1, in id order.
#[must_use]
pub fn rules() -> &'static [RuleInfo] {
    &RULES
}

/// Run every v1 rule over hook bodies.
///
/// Empty bodies (lockfile flags without a manifest) produce no hits.
/// Each rule fires at most once per hook.
#[must_use]
pub fn evaluate(hooks: &[HookFinding]) -> Vec<HeuristicFinding> {
    let mut findings = Vec::new();
    for hook in hooks {
        if hook.raw.is_empty() {
            continue;
        }
        for rule in COMPILED.iter() {
            let mat = if rule.info.id == "LW-H002" {
                rule.pattern
                    .find_iter(&hook.raw)
                    .find(|candidate| suspicious_base64(candidate.as_str()))
            } else {
                rule.pattern.find(&hook.raw)
            };
            if let Some(mat) = mat {
                let evidence = clip_evidence(&hook.raw[mat.start()..]);
                let explanation = format!(
                    "Paket {}@{} Hook `{}`: {}. Beleg: `{evidence}`.",
                    hook.package_name, hook.package_version, hook.hook, rule.reason,
                );
                findings.push(HeuristicFinding {
                    rule_id: rule.info.id,
                    description: rule.info.description,
                    weight: rule.info.weight,
                    package_name: hook.package_name.clone(),
                    package_version: hook.package_version.clone(),
                    package_path: hook.package_path.clone(),
                    hook: hook.hook.clone(),
                    explanation,
                    evidence,
                });
            }
        }
    }
    findings
}

fn clip_evidence(raw: &str) -> String {
    let flat: String = raw
        .chars()
        .map(|ch| if ch.is_whitespace() { ' ' } else { ch })
        .collect();
    let mut kept = String::new();
    for (index, ch) in flat.chars().enumerate() {
        if index == MAX_EVIDENCE {
            kept.push('…');
            break;
        }
        kept.push(ch);
    }
    kept
}

/// Length alone is not enough. Pure hex and single-alphabet runs are common
/// in minified code and must not match. A hit needs a mixed alphabet or a
/// base64 symbol, and it must not be hexadecimal.
fn suspicious_base64(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    if body.chars().count() < 80 || body.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return false;
    }
    let has_upper = body.chars().any(|ch| ch.is_ascii_uppercase());
    let has_lower = body.chars().any(|ch| ch.is_ascii_lowercase());
    let has_digit = body.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = body.chars().any(|ch| ch == '+' || ch == '/');
    has_symbol || (has_upper && has_lower && has_digit)
}

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| {
        panic!("heuristic pattern failed to compile: {pattern}: {err}");
    })
}

static RULES: [RuleInfo; 6] = [
    RuleInfo {
        id: "LW-H001",
        description: "Obfuskation im Hook (eval, new Function, fromCharCode, atob, Hex-Escapes)",
        weight: 25,
        example: r#"eval(Buffer.from("aGVsbG8=", "base64").toString())"#,
    },
    RuleInfo {
        id: "LW-H002",
        description: "Großer Base64-Block (mindestens 80 Zeichen, gemischter Zeichensatz)",
        weight: 20,
        example: "const blob = \"bG9ja3dhcmQgaGV1cmlzdGljIGZpeHR1cmUgcGF5bG9hZCB0aGF0IGlzIGxvbmcgZW5vdWdoIGZvciB0aGUgYmFzZTY0IHJ1bGU=\";",
    },
    RuleInfo {
        id: "LW-H003",
        description: "Netzwerk-Client oder Download-Werkzeug im Hook",
        weight: 15,
        example: "curl https://example.invalid/health",
    },
    RuleInfo {
        id: "LW-H004",
        description: "Download direkt in eine Shell (curl|sh oder wget|sh)",
        weight: 35,
        example: "curl https://example.invalid/setup.sh | sh",
    },
    RuleInfo {
        id: "LW-H005",
        description: "Shell-out oder child_process",
        weight: 20,
        example: "child_process.execSync(\"echo fixture\")",
    },
    RuleInfo {
        id: "LW-H006",
        description: "Zugriff auf Secret-Pfade oder Secret-Variablen",
        weight: 40,
        example: "fs.readFileSync(os.homedir() + \"/.ssh/id_rsa\")",
    },
];

static COMPILED: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    vec![
        CompiledRule {
            info: RULES[0],
            reason: "der Hook enthält obfuskierten Code",
            pattern: compile(
                r#"(?i)\beval\s*\(|\bnew\s+Function\s*\(|fromCharCode|\batob\s*\(|\bunescape\s*\(|(?:\\x[0-9a-fA-F]{2}){4,}"#,
            ),
        },
        CompiledRule {
            info: RULES[1],
            reason: "der Hook enthält einen großen Base64-Block",
            pattern: compile(r#"[A-Za-z0-9+/]{80,}={0,2}"#),
        },
        CompiledRule {
            info: RULES[2],
            reason: "der Hook spricht mit dem Netzwerk oder lädt Daten herunter",
            pattern: compile(
                r#"(?i)\bcurl\b|\bwget\b|\bfetch\s*\(|\baxios\b|\bnet\.connect\b|\bhttps?\.request\s*\(|\bhttps?\.get\s*\(|require\s*\(\s*['"]https?['"]\s*\)|require\s*\(\s*['"]node:https?['"]\s*\)"#,
            ),
        },
        CompiledRule {
            info: RULES[3],
            reason: "der Hook leitet einen Download in eine Shell",
            pattern: compile(r#"(?i)\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash)\b"#),
        },
        CompiledRule {
            info: RULES[4],
            reason: "der Hook startet einen Kindprozess oder eine Shell",
            pattern: compile(
                r#"(?i)child_process|\bexec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\(|\b(?:sh|bash)\s+-c\b|\bcmd\.exe\b|\bpowershell(?:\.exe)?\b"#,
            ),
        },
        CompiledRule {
            info: RULES[5],
            reason: "der Hook liest einen Secret-Pfad oder eine Secret-Variable",
            pattern: compile(
                r#"(?i)(?:(?:^|[/\\])\.ssh\b|(?:^|[/\\])\.npmrc\b|(?:^|[/\\])\.aws\b|~[/\\]\.config\b|[/\\]\.config(?:[/\\]|$)|NPM_TOKEN|AWS_SECRET|id_rsa)"#,
            ),
        },
    ]
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::{HookFinding, HookProvenance};

    fn hook(raw: &str) -> HookFinding {
        HookFinding {
            package_name: "fixture".to_owned(),
            package_version: "1.0.0".to_owned(),
            package_path: "node_modules/fixture".to_owned(),
            hook: "postinstall".to_owned(),
            location: "package.json#scripts.postinstall".to_owned(),
            raw: raw.to_owned(),
            provenance: HookProvenance::Manifest,
        }
    }

    fn ids(raw: &str) -> Vec<&'static str> {
        evaluate(&[hook(raw)])
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect()
    }

    #[test]
    fn engine_version_and_catalog_are_stable() {
        assert_eq!(ENGINE_VERSION, "heuristics-v1");
        let ids: Vec<_> = rules().iter().map(|rule| rule.id).collect();
        assert_eq!(
            ids,
            [
                "LW-H001", "LW-H002", "LW-H003", "LW-H004", "LW-H005", "LW-H006"
            ]
        );
        assert!(
            rules()
                .iter()
                .all(|rule| rule.weight > 0 && !rule.example.is_empty())
        );
    }

    #[test]
    fn each_rule_matches_its_inert_example() {
        for rule in rules() {
            let hit = ids(rule.example);
            assert!(
                hit.contains(&rule.id),
                "{} did not match its example, got {hit:?}",
                rule.id
            );
        }
    }

    #[test]
    fn obfuscation_rule() {
        assert_eq!(
            ids(r#"eval(Buffer.from("aGVsbG8=", "base64").toString())"#),
            ["LW-H001"]
        );
        assert!(ids(r#"const hex = "\x61\x62\x63\x64";"#).contains(&"LW-H001"));
    }

    #[test]
    fn base64_rule_ignores_short_tokens() {
        assert!(ids("const token = \"aGVsbG8=\";").is_empty());
        assert!(!ids(&format!("const blob = \"{}\";", "A".repeat(80))).contains(&"LW-H002"));
        assert!(
            !ids(&format!(
                "const hex = \"{}\";",
                "0123456789abcdef".repeat(8)
            ))
            .contains(&"LW-H002")
        );
        assert_eq!(
            ids(
                "const blob = \"bG9ja3dhcmQgaGV1cmlzdGljIGZpeHR1cmUgcGF5bG9hZCB0aGF0IGlzIGxvbmcgZW5vdWdoIGZvciB0aGUgYmFzZTY0IHJ1bGU=\";"
            ),
            ["LW-H002"]
        );
    }

    #[test]
    fn function_constructor_requires_new() {
        assert!(!ids("const name = Function(\"return 1\")").contains(&"LW-H001"));
        assert!(ids("const evil = new Function(\"return 1\")").contains(&"LW-H001"));
    }

    #[test]
    fn network_rule() {
        assert_eq!(ids("curl https://example.invalid/health"), ["LW-H003"]);
        assert!(ids("require('https').get('https://example.invalid')").contains(&"LW-H003"));
    }

    #[test]
    fn pipe_to_shell_rule() {
        let hit = ids("curl https://example.invalid/setup.sh | sh");
        assert!(hit.contains(&"LW-H003"));
        assert!(hit.contains(&"LW-H004"));
    }

    #[test]
    fn shell_out_rule() {
        assert_eq!(ids("child_process.execSync(\"echo fixture\")"), ["LW-H005"]);
        assert!(ids("bash -c \"echo fixture\"").contains(&"LW-H005"));
    }

    #[test]
    fn secret_path_rule() {
        assert_eq!(
            ids("fs.readFileSync(os.homedir() + \"/.ssh/id_rsa\")"),
            ["LW-H006"]
        );
        assert!(ids("cat ~/.npmrc").contains(&"LW-H006"));
        assert!(ids("read ~/.aws/credentials").contains(&"LW-H006"));
        assert!(ids("read ~/.config/gh/hosts.yml").contains(&"LW-H006"));
        assert!(ids("const file = \"tsconfig.json\";").is_empty());
    }

    #[test]
    fn benign_hook_and_empty_flag_are_clean() {
        assert!(ids("node-gyp rebuild").is_empty());
        assert!(ids("echo building native addon").is_empty());
        let mut flagged = hook("");
        flagged.hook = "hasInstallScript".to_owned();
        flagged.provenance = HookProvenance::LockfileFlag;
        assert!(evaluate(&[flagged]).is_empty());
    }

    #[test]
    fn explanation_names_the_package() {
        let finding = &evaluate(&[hook("curl https://example.invalid/health")])[0];
        assert!(finding.explanation.contains("fixture@1.0.0"));
        assert!(finding.explanation.contains("postinstall"));
        assert!(finding.explanation.contains("curl"));
    }
}
