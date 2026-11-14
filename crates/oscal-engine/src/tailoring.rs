//! Baseline Catalog Tailoring & CSP Inheritance Evaluation Engine
//! Per ADR-0005 §5.6 and Milestone 4 Specifications

use chrono::{DateTime, Utc};
use oscal_types::{PoamItem, Property};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::gate_policy::{
    GatePolicyConfigCatalogInheritanceValue, GatePolicyConfigCatalogTailoring,
};
use crate::{canonicalize_control_id, EvidenceTier, PRIME_OSCAL_NAMESPACE};

/// Control disposition within the unified satisfaction model
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ControlDisposition {
    Workspace {
        component: String,
        achieved_tier: EvidenceTier,
    },
    Inherited {
        source_id: String,
    },
    Unsatisfied,
}

/// Tailored baseline evaluation report
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailoredBaselineReport {
    pub scope: Option<String>,
    pub in_scope_controls: BTreeSet<String>,
    pub excluded_controls: BTreeSet<String>,
    pub c_tailored: BTreeSet<String>,
    pub denominator: usize,
}

/// Single inheritance source evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritanceSourceEvaluation {
    pub source_id: String,
    pub title: String,
    pub leveraged_authorization_uuid: String,
    pub boundary_description: Option<String>,
    pub attestation_expiry: String,
    pub expiry_datetime: DateTime<Utc>,
    pub is_active: bool,
    pub controls: BTreeSet<String>,
}

/// Full catalog inheritance report
#[derive(Debug, Clone)]
pub struct CatalogInheritanceReport {
    pub sources: BTreeMap<String, InheritanceSourceEvaluation>,
    pub active_inherited_controls: BTreeMap<String, Vec<String>>,
    pub expired_inherited_controls: BTreeMap<String, Vec<String>>,
}

/// Retrieve effective current time supporting test injection and OSCAL_NOW env override
pub fn get_effective_clock(injected: Option<DateTime<Utc>>) -> DateTime<Utc> {
    if let Some(t) = injected {
        return t;
    }
    if let Ok(env_str) = std::env::var("OSCAL_NOW") {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(&env_str) {
            return parsed.with_timezone(&Utc);
        }
    }
    Utc::now()
}

static PINNED_CATALOG_CONTROLS: OnceLock<BTreeSet<String>> = OnceLock::new();

/// Extract all canonical control IDs from a parsed NIST OSCAL catalog JSON Value
pub fn extract_control_ids_from_catalog_json(val: &serde_json::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(cat) = val.get("catalog") {
        if let Some(groups) = cat.get("groups").and_then(|v| v.as_array()) {
            for g in groups {
                if let Some(ctrls) = g.get("controls").and_then(|v| v.as_array()) {
                    for c in ctrls {
                        extract_control_ids_recursive(c, &mut out);
                    }
                }
            }
        }
        if let Some(ctrls) = cat.get("controls").and_then(|v| v.as_array()) {
            for c in ctrls {
                extract_control_ids_recursive(c, &mut out);
            }
        }
    }
    out
}

fn extract_control_ids_recursive(node: &serde_json::Value, out: &mut BTreeSet<String>) {
    if let Some(id) = node.get("id").and_then(|v| v.as_str()) {
        out.insert(canonicalize_control_id(id));
    }
    if let Some(sub) = node.get("controls").and_then(|v| v.as_array()) {
        for c in sub {
            extract_control_ids_recursive(c, out);
        }
    }
}

/// Load the control IDs from the pinned NIST SP 800-53 Rev. 5 catalog
pub fn get_pinned_catalog_control_ids() -> &'static BTreeSet<String> {
    PINNED_CATALOG_CONTROLS.get_or_init(|| {
        let candidate_paths = [
            Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json"),
            Path::new("../schemas/catalogs/NIST_SP_800-53_rev5_catalog.json"),
            Path::new("../../schemas/catalogs/NIST_SP_800-53_rev5_catalog.json"),
        ];
        for p in &candidate_paths {
            if p.exists() {
                if let Ok(s) = std::fs::read_to_string(p) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) {
                        let ids = extract_control_ids_from_catalog_json(&val);
                        if !ids.is_empty() {
                            return ids;
                        }
                    }
                }
            }
        }
        BTreeSet::new()
    })
}

/// Load control IDs from a specific catalog path
pub fn load_catalog_control_ids_from_file(path: &Path) -> Result<BTreeSet<String>, String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read catalog file {}: {}", path.display(), e))?;
    let val: serde_json::Value = serde_json::from_str(&s)
        .map_err(|e| format!("Failed to parse catalog JSON {}: {}", path.display(), e))?;
    let ids = extract_control_ids_from_catalog_json(&val);
    if ids.is_empty() {
        Err(format!("Catalog file {} contains zero controls", path.display()))
    } else {
        Ok(ids)
    }
}

/// Evaluate tailoring overlay producing tailored baseline set C_tailored and denominator ‖C_tailored‖
pub fn evaluate_tailoring_overlay(
    tailoring: &GatePolicyConfigCatalogTailoring,
    catalog_controls: &BTreeSet<String>,
) -> Result<TailoredBaselineReport, Vec<String>> {
    let mut errors = Vec::new();

    // 1. Collect declared in-scope controls (combining in_scope_controls and include_controls)
    let mut in_scope_raw = tailoring.in_scope_controls.clone();
    in_scope_raw.extend(tailoring.include_controls.clone());

    // 2. Collect declared excluded controls (combining excluded_controls and exclude_controls)
    let mut excluded_raw = tailoring.excluded_controls.clone();
    excluded_raw.extend(tailoring.exclude_controls.clone());

    let mut seen_in_scope: HashMap<String, String> = HashMap::new();
    let mut in_scope_set = BTreeSet::new();

    for raw in &in_scope_raw {
        let canonical = canonicalize_control_id(raw);
        if !catalog_controls.is_empty() && !catalog_controls.contains(&canonical) {
            errors.push(format!(
                "[E-OSCAL-008] Tailoring in-scope references unknown control '{}' (canonical '{}') not present in pinned catalog",
                raw, canonical
            ));
        }
        if let Some(prev) = seen_in_scope.insert(canonical.clone(), raw.clone()) {
            if prev != *raw {
                errors.push(format!(
                    "Duplicate in-scope control declaration: '{}' and '{}' both map to canonical '{}'",
                    prev, raw, canonical
                ));
            } else {
                errors.push(format!(
                    "Duplicate in-scope control declaration: '{}' (canonical '{}') declared multiple times",
                    raw, canonical
                ));
            }
        }
        in_scope_set.insert(canonical);
    }

    let mut seen_excluded: HashMap<String, String> = HashMap::new();
    let mut excluded_set = BTreeSet::new();

    for raw in &excluded_raw {
        let canonical = canonicalize_control_id(raw);
        if !catalog_controls.is_empty() && !catalog_controls.contains(&canonical) {
            errors.push(format!(
                "[E-OSCAL-008] Tailoring excluded references unknown control '{}' (canonical '{}') not present in pinned catalog",
                raw, canonical
            ));
        }
        if let Some(prev) = seen_excluded.insert(canonical.clone(), raw.clone()) {
            if prev != *raw {
                errors.push(format!(
                    "Duplicate excluded control declaration: '{}' and '{}' both map to canonical '{}'",
                    prev, raw, canonical
                ));
            } else {
                errors.push(format!(
                    "Duplicate excluded control declaration: '{}' (canonical '{}') declared multiple times",
                    raw, canonical
                ));
            }
        }
        excluded_set.insert(canonical);
    }

    // 3. Check for conflicting in-scope and excluded entries
    for canonical in seen_in_scope.keys() {
        if let Some(ex_raw) = seen_excluded.get(canonical) {
            let in_raw = &seen_in_scope[canonical];
            errors.push(format!(
                "Conflicting tailoring declaration: Control '{}' (canonical '{}') declared in both in-scope ('{}') and excluded ('{}') sets",
                canonical, canonical, in_raw, ex_raw
            ));
        }
    }

    // 4. Compute C_tailored
    let mut c_tailored = BTreeSet::new();
    let base_set = if in_scope_set.is_empty() {
        catalog_controls.clone()
    } else {
        in_scope_set.clone()
    };

    for canonical in &base_set {
        if !excluded_set.contains(canonical) {
            c_tailored.insert(canonical.clone());
        }
    }

    // 5. Fail closed if tailored baseline is empty
    if errors.is_empty() && c_tailored.is_empty() {
        errors.push("Tailored baseline C_tailored is empty; coverage denominator cannot be zero".to_string());
    }

    if errors.is_empty() {
        let denominator = c_tailored.len();
        Ok(TailoredBaselineReport {
            scope: tailoring.scope.map(|s| s.to_string()),
            in_scope_controls: in_scope_set,
            excluded_controls: excluded_set,
            c_tailored,
            denominator,
        })
    } else {
        Err(errors)
    }
}

/// Evaluate catalog inheritance sources and partition into active vs lapsed
pub fn evaluate_catalog_inheritance(
    inheritance_map: &HashMap<String, GatePolicyConfigCatalogInheritanceValue>,
    catalog_controls: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> Result<CatalogInheritanceReport, Vec<String>> {
    let mut errors = Vec::new();
    let mut sources = BTreeMap::new();
    let mut active_inherited_controls: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut expired_inherited_controls: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (source_id, inh) in inheritance_map {
        let expiry_dt = match DateTime::parse_from_rfc3339(&inh.attestation_expiry) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(e) => {
                errors.push(format!(
                    "Inheritance source '{}' has invalid attestation_expiry timestamp '{}': {}",
                    source_id, inh.attestation_expiry, e
                ));
                continue;
            }
        };

        let is_active = expiry_dt >= now;
        let mut source_controls = BTreeSet::new();

        for raw_ctrl in &inh.controls {
            let canonical = canonicalize_control_id(raw_ctrl);
            if !catalog_controls.is_empty() && !catalog_controls.contains(&canonical) {
                errors.push(format!(
                    "[E-OSCAL-008] Inheritance source '{}' references unknown catalog control '{}' (canonical '{}') not present in pinned catalog",
                    source_id, raw_ctrl, canonical
                ));
            }
            source_controls.insert(canonical.clone());

            if is_active {
                active_inherited_controls
                    .entry(canonical)
                    .or_default()
                    .push(source_id.clone());
            } else {
                expired_inherited_controls
                    .entry(canonical)
                    .or_default()
                    .push(source_id.clone());
            }
        }

        sources.insert(
            source_id.clone(),
            InheritanceSourceEvaluation {
                source_id: source_id.clone(),
                title: inh.title.clone(),
                leveraged_authorization_uuid: inh.leveraged_authorization_uuid.clone(),
                boundary_description: inh.boundary_description.clone(),
                attestation_expiry: inh.attestation_expiry.clone(),
                expiry_datetime: expiry_dt,
                is_active,
                controls: source_controls,
            },
        );
    }

    if errors.is_empty() {
        Ok(CatalogInheritanceReport {
            sources,
            active_inherited_controls,
            expired_inherited_controls,
        })
    } else {
        Err(errors)
    }
}

/// Synthesize a deterministic schema-valid POA&M item for an expired external inheritance source
pub fn synthesize_expired_attestation_poam_item(
    canonical_id: &str,
    source_id: &str,
    attestation_expiry: &str,
    now: DateTime<Utc>,
) -> PoamItem {
    let item_uuid = Uuid::new_v5(
        &PRIME_OSCAL_NAMESPACE,
        format!("{}:{}:{}", canonical_id, source_id, attestation_expiry).as_bytes(),
    );

    PoamItem {
        uuid: item_uuid,
        title: format!(
            "Expired CSP inheritance attestation for control {} ({})",
            canonical_id, source_id
        ),
        description: format!(
            "The external authorization attestation package for source '{}' covering control '{}' expired at {}. An updated authorization package or POA&M remediation is required.",
            source_id, canonical_id, attestation_expiry
        ),
        props: vec![
            Property {
                name: "control-id".to_string(),
                value: canonical_id.to_string(),
                ns: None,
            },
            Property {
                name: "inheritance-source".to_string(),
                value: source_id.to_string(),
                ns: None,
            },
            Property {
                name: "status".to_string(),
                value: "inherited-pending-attestation".to_string(),
                ns: None,
            },
            Property {
                name: "attestation-expiry".to_string(),
                value: attestation_expiry.to_string(),
                ns: None,
            },
            Property {
                name: "evaluation-time".to_string(),
                value: now.to_rfc3339(),
                ns: None,
            },
        ],
        related_findings: vec![],
        related_observations: vec![],
        remarks: Some(format!("Current evaluation time: {}", now.to_rfc3339())),
    }
}

/// Derives a TailoredBaselineReport directly from an authoritative resolved catalog Value.
pub fn derive_tailored_baseline_from_resolved_catalog(
    resolved_catalog: &serde_json::Value,
) -> Result<TailoredBaselineReport, String> {
    let control_ids = extract_control_ids_from_catalog_json(resolved_catalog);
    if control_ids.is_empty() {
        return Err("Resolved catalog contains zero controls; tailored baseline cannot be empty".to_string());
    }
    let title = resolved_catalog
        .get("catalog")
        .and_then(|c| c.get("metadata"))
        .and_then(|m| m.get("title"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());

    Ok(TailoredBaselineReport {
        scope: title,
        in_scope_controls: control_ids.clone(),
        excluded_controls: BTreeSet::new(),
        denominator: control_ids.len(),
        c_tailored: control_ids,
    })
}

/// Synthesizes an in-memory OSCAL 1.1.0 Profile Value from a deprecated `[catalog.tailoring]` configuration.
/// Emits a deprecation warning to notify consumers to migrate to OSCAL Profile.
pub fn synthesize_profile_from_tailoring(
    tailoring: &GatePolicyConfigCatalogTailoring,
    catalog_path: &Path,
    injected_now: Option<DateTime<Utc>>,
) -> serde_json::Value {
    eprintln!("\x1b[1;33m[DEPRECATION: catalog.tailoring is deprecated; migrate to OSCAL Profile]\x1b[0m");

    let now = get_effective_clock(injected_now);
    let now_str = now.to_rfc3339();

    let mut in_scope = tailoring.in_scope_controls.clone();
    in_scope.extend(tailoring.include_controls.clone());

    let mut excluded = tailoring.excluded_controls.clone();
    excluded.extend(tailoring.exclude_controls.clone());

    // Canonicalize IDs for uniform selector matching
    let mut normalized_in_scope: Vec<String> = in_scope.into_iter().map(|c| canonicalize_control_id(&c)).collect();
    normalized_in_scope.sort();
    normalized_in_scope.dedup();

    let mut normalized_excluded: Vec<String> = excluded.into_iter().map(|c| canonicalize_control_id(&c)).collect();
    normalized_excluded.sort();
    normalized_excluded.dedup();

    let mut hasher_inputs = normalized_in_scope.clone();
    hasher_inputs.extend(normalized_excluded.clone());
    let profile_uuid = Uuid::new_v5(
        &PRIME_OSCAL_NAMESPACE,
        format!("synthetic-profile:{}", hasher_inputs.join(",")).as_bytes(),
    );

    let cat_href = catalog_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("NIST_SP_800-53_rev5_catalog.json");

    let mut import_obj = json!({
        "href": cat_href
    });

    if !normalized_in_scope.is_empty() {
        import_obj["include-controls"] = json!([
            {
                "with-ids": normalized_in_scope
            }
        ]);
    }

    if !normalized_excluded.is_empty() {
        import_obj["exclude-controls"] = json!([
            {
                "with-ids": normalized_excluded
            }
        ]);
    }

    json!({
        "profile": {
            "uuid": profile_uuid.to_string(),
            "metadata": {
                "title": "Synthetic Baseline Profile from Deprecated [catalog.tailoring]",
                "published": now_str,
                "last-modified": now_str,
                "version": "1.0.0",
                "oscal-version": "1.1.0",
                "props": [
                    {
                        "name": "tailoring-mode",
                        "value": "deprecated-shim"
                    }
                ]
            },
            "imports": [
                import_obj
            ]
        }
    })
}

/// Synthesizes a default workspace profile from declared control IDs.
pub fn synthesize_workspace_declared_profile(
    control_ids: &[String],
    catalog_path: &Path,
    injected_now: Option<DateTime<Utc>>,
) -> serde_json::Value {
    let now = get_effective_clock(injected_now);
    let now_str = now.to_rfc3339();

    let mut sorted_ids: Vec<String> = control_ids.iter().map(|c| canonicalize_control_id(c)).collect();
    sorted_ids.sort();
    sorted_ids.dedup();

    let profile_uuid = Uuid::new_v5(
        &PRIME_OSCAL_NAMESPACE,
        format!("workspace-declared-profile:{}", sorted_ids.join(",")).as_bytes(),
    );

    let cat_href = catalog_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("NIST_SP_800-53_rev5_catalog.json");

    json!({
        "profile": {
            "uuid": profile_uuid.to_string(),
            "metadata": {
                "title": "PRIME Workspace Declared Controls Baseline Profile",
                "published": now_str,
                "last-modified": now_str,
                "version": "1.0.0",
                "oscal-version": "1.1.0",
                "props": [
                    {
                        "name": "baseline-mode",
                        "value": "declared-controls"
                    }
                ]
            },
            "imports": [
                {
                    "href": cat_href,
                    "include-controls": [
                        {
                            "with-ids": sorted_ids
                        }
                    ]
                }
            ]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_catalog_controls() -> BTreeSet<String> {
        let mut s = BTreeSet::new();
        s.insert("ac-1".to_string());
        s.insert("ac-2.1".to_string());
        s.insert("sc-13".to_string());
        s.insert("si-7".to_string());
        s.insert("si-7.1".to_string());
        s.insert("pe-1".to_string());
        s.insert("pe-2".to_string());
        s.insert("pe-3".to_string());
        s
    }

    #[test]
    fn test_tailoring_overlay_computes_c_tailored_and_denominator() {
        let catalog = mock_catalog_controls();
        let tailoring = GatePolicyConfigCatalogTailoring {
            in_scope_controls: vec![
                "AC-2(1)".to_string(),
                "SC-13".to_string(),
                "SI-7(1)".to_string(),
            ],
            excluded_controls: vec!["PE-1".to_string()],
            ..Default::default()
        };

        let report = evaluate_tailoring_overlay(&tailoring, &catalog)
            .expect("Tailoring overlay evaluation succeeds");
        assert_eq!(report.denominator, 3);
        assert_eq!(report.c_tailored.len(), 3);
        assert!(report.c_tailored.contains("ac-2.1"));
        assert!(report.c_tailored.contains("sc-13"));
        assert!(report.c_tailored.contains("si-7.1"));
        assert!(!report.c_tailored.contains("pe-1"), "PE-1 was excluded");

        // Full catalog baseline with excluded control omitted from denominator
        let tailoring_catalog_base = GatePolicyConfigCatalogTailoring {
            in_scope_controls: vec![],
            excluded_controls: vec!["PE-1".to_string()],
            ..Default::default()
        };
        let report2 = evaluate_tailoring_overlay(&tailoring_catalog_base, &catalog)
            .expect("Tailoring overlay with full catalog baseline succeeds");
        assert_eq!(report2.denominator, 7);
        assert!(!report2.c_tailored.contains("pe-1"), "PE-1 omitted from denominator");
    }

    #[test]
    fn test_tailoring_overlay_conflicting_in_scope_and_excluded() {
        let catalog = mock_catalog_controls();
        let tailoring = GatePolicyConfigCatalogTailoring {
            in_scope_controls: vec!["SI-7(1)".to_string()],
            excluded_controls: vec!["si-7.1".to_string()], // Canonical collision
            ..Default::default()
        };

        let errs = evaluate_tailoring_overlay(&tailoring, &catalog)
            .expect_err("Conflicting tailoring should fail closed");
        assert!(
            errs.iter().any(|e| e.contains("Conflicting tailoring declaration") && e.contains("si-7.1")),
            "Expected conflicting tailoring diagnostic, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_tailoring_overlay_unknown_control_fails_closed() {
        let catalog = mock_catalog_controls();
        let tailoring = GatePolicyConfigCatalogTailoring {
            in_scope_controls: vec!["UNKNOWN-99".to_string()],
            ..Default::default()
        };

        let errs = evaluate_tailoring_overlay(&tailoring, &catalog)
            .expect_err("Unknown control should fail closed");
        assert!(
            errs.iter().any(|e| e.contains("Tailoring in-scope references unknown control 'UNKNOWN-99'")),
            "Expected unknown control error, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_tailoring_overlay_duplicate_in_scope_fails() {
        let catalog = mock_catalog_controls();
        let tailoring = GatePolicyConfigCatalogTailoring {
            in_scope_controls: vec!["SI-7(1)".to_string(), "si-7.1".to_string()],
            ..Default::default()
        };

        let errs = evaluate_tailoring_overlay(&tailoring, &catalog)
            .expect_err("Duplicate in-scope controls should fail");
        assert!(
            errs.iter().any(|e| e.contains("Duplicate in-scope control declaration")),
            "Expected duplicate in-scope error, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_tailoring_overlay_empty_baseline_fails() {
        let mut single_item_catalog = BTreeSet::new();
        single_item_catalog.insert("ac-1".to_string());
        let tailoring = GatePolicyConfigCatalogTailoring {
            in_scope_controls: vec![],
            excluded_controls: vec!["AC-1".to_string()],
            ..Default::default()
        };

        let errs = evaluate_tailoring_overlay(&tailoring, &single_item_catalog)
            .expect_err("Empty tailored baseline should fail closed");
        assert!(
            errs.iter().any(|e| e.contains("Tailored baseline C_tailored is empty")),
            "Expected empty baseline error, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_inheritance_active_and_expired_partitioning() {
        let catalog = mock_catalog_controls();
        let now = DateTime::parse_from_rfc3339("2026-11-10T00:00:00Z").unwrap().with_timezone(&Utc);

        let mut map = HashMap::new();
        map.insert(
            "aws_govcloud".to_string(),
            GatePolicyConfigCatalogInheritanceValue {
                title: "AWS GovCloud".to_string(),
                leveraged_authorization_uuid: "uuid-1".to_string(),
                boundary_description: Some("Data center physical boundary".to_string()),
                attestation_expiry: "2027-03-15T00:00:00Z".to_string(), // Active
                controls: vec!["PE-1".to_string(), "PE-2".to_string()],
            },
        );
        map.insert(
            "legacy_provider".to_string(),
            GatePolicyConfigCatalogInheritanceValue {
                title: "Legacy Hosting".to_string(),
                leveraged_authorization_uuid: "uuid-2".to_string(),
                boundary_description: None,
                attestation_expiry: "2025-01-01T00:00:00Z".to_string(), // Expired
                controls: vec!["PE-3".to_string()],
            },
        );

        let report = evaluate_catalog_inheritance(&map, &catalog, now)
            .expect("Inheritance evaluation succeeds");
        assert_eq!(report.sources.len(), 2);
        assert!(report.sources["aws_govcloud"].is_active);
        assert!(!report.sources["legacy_provider"].is_active);

        assert!(report.active_inherited_controls.contains_key("pe-1"));
        assert!(report.active_inherited_controls.contains_key("pe-2"));
        assert!(report.expired_inherited_controls.contains_key("pe-3"));
    }

    #[test]
    fn test_deterministic_expired_poam_item_synthesis() {
        let now = DateTime::parse_from_rfc3339("2026-11-10T12:00:00Z").unwrap().with_timezone(&Utc);
        let item1 = synthesize_expired_attestation_poam_item("sc-13", "aws_govcloud", "2025-01-01T00:00:00Z", now);
        let item2 = synthesize_expired_attestation_poam_item("sc-13", "aws_govcloud", "2025-01-01T00:00:00Z", now);

        assert_eq!(item1.uuid, item2.uuid, "UUIDv5 must be strictly deterministic across calls");
        let json1 = serde_json::to_string(&item1).unwrap();
        let json2 = serde_json::to_string(&item2).unwrap();
        assert_eq!(json1, json2, "POA&M JSON serialization must be byte-for-byte deterministic");
    }

    #[test]
    fn test_clock_injection_override() {
        let custom_time = DateTime::parse_from_rfc3339("2028-01-01T00:00:00Z").unwrap().with_timezone(&Utc);
        let eff = get_effective_clock(Some(custom_time));
        assert_eq!(eff, custom_time);

        unsafe {
            std::env::set_var("OSCAL_NOW", "2029-06-15T08:30:00Z");
        }
        let env_eff = get_effective_clock(None);
        assert_eq!(env_eff.to_rfc3339(), "2029-06-15T08:30:00+00:00");
        unsafe {
            std::env::remove_var("OSCAL_NOW");
        }
    }

    #[test]
    fn test_tailoring_shim_synthesizes_profile_with_include_and_exclude() {
        let tailoring = GatePolicyConfigCatalogTailoring {
            in_scope_controls: vec!["ac-1".to_string(), "si-7".to_string()],
            include_controls: vec!["ca-2".to_string()],
            excluded_controls: vec!["si-7.1".to_string()],
            exclude_controls: vec![],
            scope: None,
        };
        let cat_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let now = DateTime::parse_from_rfc3339("2026-11-11T12:00:00Z").unwrap().with_timezone(&Utc);

        let synth = synthesize_profile_from_tailoring(&tailoring, cat_path, Some(now));
        assert!(crate::validate_profile(&synth).is_ok(), "Synthetic profile must strictly validate against official NIST OSCAL Profile schema");

        let profile_obj = synth["profile"].as_object().expect("profile object");
        let metadata = profile_obj["metadata"].as_object().expect("metadata");
        let props = metadata["props"].as_array().expect("props array");
        assert!(props.iter().any(|p| p["name"] == "tailoring-mode" && p["value"] == "deprecated-shim"));

        let imports = profile_obj["imports"].as_array().expect("imports array");
        assert_eq!(imports.len(), 1);
        let inc = imports[0]["include-controls"][0]["with-ids"].as_array().expect("with-ids");
        let inc_ids: Vec<&str> = inc.iter().filter_map(|v| v.as_str()).collect();
        assert!(inc_ids.contains(&"ac-1"));
        assert!(inc_ids.contains(&"si-7"));
        assert!(inc_ids.contains(&"ca-2"));

        let exc = imports[0]["exclude-controls"][0]["with-ids"].as_array().expect("with-ids");
        let exc_ids: Vec<&str> = exc.iter().filter_map(|v| v.as_str()).collect();
        assert!(exc_ids.contains(&"si-7.1"));
    }

    #[test]
    fn test_workspace_declared_profile_synthesizes_valid_profile() {
        let controls = vec!["SI-7".to_string(), "CM-7".to_string(), "CA-2".to_string()];
        let cat_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let now = DateTime::parse_from_rfc3339("2026-11-11T12:00:00Z").unwrap().with_timezone(&Utc);

        let synth = synthesize_workspace_declared_profile(&controls, cat_path, Some(now));
        assert!(crate::validate_profile(&synth).is_ok(), "Workspace declared profile must validate against schema");

        let profile_obj = synth["profile"].as_object().expect("profile");
        let metadata = profile_obj["metadata"].as_object().expect("metadata");
        let props = metadata["props"].as_array().expect("props");
        assert!(props.iter().any(|p| p["name"] == "baseline-mode" && p["value"] == "declared-controls"));
    }

    #[test]
    fn test_tailoring_shim_resolves_to_valid_catalog() {
        let test_dir = Path::new("target/test_tailoring_shim_resolve");
        let _ = std::fs::remove_dir_all(test_dir);
        std::fs::create_dir_all(test_dir).unwrap();

        let tailoring = GatePolicyConfigCatalogTailoring {
            in_scope_controls: vec!["ac-1".to_string(), "ac-2".to_string()],
            include_controls: vec![],
            excluded_controls: vec!["ac-2".to_string()],
            exclude_controls: vec![],
            scope: None,
        };
        let cat_path = Path::new("schemas/catalogs/NIST_SP_800-53_rev5_catalog.json");
        let now = DateTime::parse_from_rfc3339("2026-11-11T12:00:00Z").unwrap().with_timezone(&Utc);

        let synth = synthesize_profile_from_tailoring(&tailoring, cat_path, Some(now));
        let profile_file = test_dir.join("profile.json");
        std::fs::write(&profile_file, serde_json::to_string_pretty(&synth).unwrap()).unwrap();

        let resolved = crate::resolve_profile(&profile_file, cat_path, Path::new("."), Some(now))
            .expect("Shim profile must resolve into concrete catalog");

        assert!(crate::validate_catalog(&resolved).is_ok());
        let report = derive_tailored_baseline_from_resolved_catalog(&resolved)
            .expect("Must derive tailored baseline report from resolved catalog");

        assert_eq!(report.denominator, 1);
        assert!(report.c_tailored.contains("ac-1"));
        assert!(!report.c_tailored.contains("ac-2"));

        let _ = std::fs::remove_dir_all(test_dir);
    }
}
