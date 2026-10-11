//! CVSS v3.0/v3.1 base score.
//!
//! The implementation follows the FIRST rounding rules so severity bands do
//! not depend on formatting. CVSS v2 and v4 vectors are not scored here.

/// Compute a CVSS v3 base score, rounded up to one decimal.
#[must_use]
pub fn cvss31_base_score(vector: &str) -> Option<f64> {
    let vector = vector.trim();
    let body = vector
        .strip_prefix("CVSS:3.1/")
        .or_else(|| vector.strip_prefix("CVSS:3.0/"))?;
    let mut metrics = std::collections::BTreeMap::new();
    for part in body.split('/') {
        let (key, value) = part.split_once(':')?;
        metrics.insert(key, value);
    }
    let av = metric(metrics.get("AV").copied(), av_weight)?;
    let ac = metric(metrics.get("AC").copied(), ac_weight)?;
    let ui = metric(metrics.get("UI").copied(), ui_weight)?;
    let scope_changed = match metrics.get("S").copied()? {
        "C" => true,
        "U" => false,
        _ => return None,
    };
    let pr = pr_weight(metrics.get("PR").copied()?, scope_changed)?;
    let confidentiality = metric(metrics.get("C").copied(), cia_weight)?;
    let integrity = metric(metrics.get("I").copied(), cia_weight)?;
    let availability = metric(metrics.get("A").copied(), cia_weight)?;

    let iss = 1.0 - ((1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(roundup(raw))
}

/// Map a base score onto Lockward's severity bands.
#[must_use]
pub fn severity_from_score(score: f64) -> super::Severity {
    if score >= 9.0 {
        super::Severity::Critical
    } else if score >= 7.0 {
        super::Severity::High
    } else if score >= 4.0 {
        super::Severity::Medium
    } else if score > 0.0 {
        super::Severity::Low
    } else {
        super::Severity::Unknown
    }
}

pub(super) fn format_score(score: f64) -> String {
    format!("{score:.1}")
}

fn metric(value: Option<&str>, weights: fn(&str) -> Option<f64>) -> Option<f64> {
    weights(value?)
}

fn av_weight(value: &str) -> Option<f64> {
    match value {
        "N" => Some(0.85),
        "A" => Some(0.62),
        "L" => Some(0.55),
        "P" => Some(0.2),
        _ => None,
    }
}

fn ac_weight(value: &str) -> Option<f64> {
    match value {
        "L" => Some(0.77),
        "H" => Some(0.44),
        _ => None,
    }
}

fn ui_weight(value: &str) -> Option<f64> {
    match value {
        "N" => Some(0.85),
        "R" => Some(0.62),
        _ => None,
    }
}

fn cia_weight(value: &str) -> Option<f64> {
    match value {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    }
}

fn pr_weight(value: &str, scope_changed: bool) -> Option<f64> {
    match (value, scope_changed) {
        ("N", _) => Some(0.85),
        ("L", false) => Some(0.62),
        ("L", true) => Some(0.68),
        ("H", false) => Some(0.27),
        ("H", true) => Some(0.5),
        _ => None,
    }
}

/// FIRST `Roundup`: ceiling to one decimal, with exact tenths left unchanged.
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        (int_input as f64) / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_network_vector_is_9_8() {
        let score = cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((score - 9.8).abs() < f64::EPSILON);
        assert_eq!(severity_from_score(score), super::super::Severity::Critical);
    }

    #[test]
    fn low_confidentiality_vector_is_5_3() {
        let score = cvss31_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N").unwrap();
        assert!((score - 5.3).abs() < f64::EPSILON);
        assert_eq!(severity_from_score(score), super::super::Severity::Medium);
    }

    #[test]
    fn rejects_unknown_vectors() {
        assert!(cvss31_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").is_none());
        assert!(cvss31_base_score("not-a-vector").is_none());
    }
}
