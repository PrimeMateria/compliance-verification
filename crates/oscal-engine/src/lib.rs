//! OSCAL Engine - Synthesizes NIST OSCAL 1.1.0 Assessment Results and POA&M Documents
//! Per ADR-0013 / PRIME-ADR-003 and INV-PRIME-007

pub mod ar;
pub mod evidence;
pub mod gate_policy;
pub mod history;
pub mod monitor;
pub mod poam;
pub mod pcrate;
pub mod profile;
pub mod registry;
pub mod sap;
pub mod ssp;
pub mod tailoring;
pub use ar::*;
pub use evidence::*;
pub use gate_policy::{DeclarationKind, EvidenceTier, GatePolicyConfig};
pub use history::*;
pub use monitor::*;
pub use pcrate::*;
pub use poam::*;
pub use profile::*;
pub use registry::*;
pub use sap::*;
pub use ssp::*;
pub use tailoring::{CatalogInheritanceReport, ControlDisposition, TailoredBaselineReport};

use chrono::Utc;
use oscal_types::*;
use uuid::Uuid;

/// Vendored schemas baked into the binary for validate-before-write guarantees
pub const AR_SCHEMA_STR: &str = include_str!("../../../schemas/oscal_assessment-results_schema.json");
pub const POAM_SCHEMA_STR: &str = include_str!("../../../schemas/oscal_poam_schema.json");
pub const SSP_SCHEMA_STR: &str = include_str!("../../../schemas/oscal_ssp_schema.json");
pub const SAP_SCHEMA_STR: &str = include_str!("../../../schemas/oscal_assessment-plan_schema.json");
pub const PROFILE_SCHEMA_STR: &str = include_str!("../../../schemas/oscal_profile_schema.json");
pub const CATALOG_SCHEMA_STR: &str = include_str!("../../../schemas/oscal_catalog_schema.json");
pub const EVIDENCE_SCHEMA_STR: &str = include_str!("../../../schemas/evidence.schema.json");
pub const TRESTLE_ATTESTATION_SCHEMA_STR: &str = include_str!("../../../schemas/trestle-attestation.schema.json");
pub const GATE_RULE_REGISTRY_SCHEMA_STR: &str = include_str!("../../../schemas/gate-rule-registry.schema.json");
pub const GATE_RULE_REGISTRY_STR: &str = include_str!("../../../gate-rule-registry.toml");
pub const PCRATE_MANIFEST_SCHEMA_STR: &str = include_str!("../../../schemas/pcrate-manifest.schema.json");
pub const SUPPRESSED_FINDINGS_SCHEMA_STR: &str = include_str!("../../../schemas/suppressed-findings.schema.json");
pub const CONTROL_ID_MAP_STR: &str = include_str!("../control-id-map.toml");

/// Deterministic namespace UUID for PRIME OSCAL synthesis:
/// RFC 4122 UUIDv5 DNS namespace hashed over "nist.gov:oscal:prime-verification"
pub const PRIME_OSCAL_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

pub struct SynthesisInput {
    pub title: String,
    pub component_title: String,
    pub control_id: String,
    pub target_symbol: String,
    pub required_tier: EvidenceTier,
    pub achieved_tier: EvidenceTier,
    pub kani_passed: bool,
    pub lean_sorry_detected: bool,
    pub failure_reason: Option<String>,
    pub is_waived: bool,
    pub waiver_mode: gate_policy::GatePolicyConfigPolicyWaiverMode,
}

pub struct SynthesizedComplianceBundle {
    pub assessment_results: OscalAssessmentResultsDocument,
    pub poam: Option<OscalPoamDocument>,
    pub suppressed_findings: Option<SuppressedFindingsDocument>,
}

impl SynthesizedComplianceBundle {
    /// Strict validate-before-write against official NIST OSCAL 1.1.0 JSON Schemas
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let ar_json = serde_json::to_value(&self.assessment_results)
            .map_err(|e| vec![format!("AR serialization error: {}", e)])?;

        let mut errors = Vec::new();
        if let Err(mut ar_errs) = validate_assessment_results(&ar_json) {
            errors.append(&mut ar_errs);
        }

        if let Some(poam_doc) = &self.poam {
            let poam_json = serde_json::to_value(poam_doc)
                .map_err(|e| vec![format!("POAM serialization error: {}", e)])?;
            if let Err(mut poam_errs) = validate_poam(&poam_json) {
                errors.append(&mut poam_errs);
            }
        }

        if let Some(suppressed_doc) = &self.suppressed_findings {
            let suppressed_json = serde_json::to_value(suppressed_doc)
                .map_err(|e| vec![format!("Suppressed findings serialization error: {}", e)])?;
            if let Err(mut supp_errs) = validate_suppressed_findings(&suppressed_json) {
                errors.append(&mut supp_errs);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Validate any JSON Value against the vendored NIST OSCAL Assessment Results 1.1.0 schema
pub fn validate_assessment_results(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(AR_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored AR schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile AR schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored NIST OSCAL POA&M 1.1.0 schema
pub fn validate_poam(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(POAM_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored POAM schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile POAM schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored Suppressed Findings schema
pub fn validate_suppressed_findings(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(SUPPRESSED_FINDINGS_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored Suppressed Findings schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile Suppressed Findings schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored NIST OSCAL SSP 1.1.0 schema
pub fn validate_system_security_plan(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(SSP_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored SSP schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile SSP schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored NIST OSCAL Assessment Plan (SAP) 1.1.0 schema
pub fn validate_assessment_plan(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(SAP_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored SAP schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile SAP schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored NIST OSCAL Profile 1.1.0 schema
pub fn validate_profile(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(PROFILE_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored Profile schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile Profile schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored NIST OSCAL Catalog 1.1.0 schema
pub fn validate_catalog(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(CATALOG_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored Catalog schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile Catalog schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored Evidence 1.0.0 schema
pub fn validate_evidence(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(EVIDENCE_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored Evidence schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile Evidence schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored Trestle Attestation 1.0.0 schema
pub fn validate_trestle_attestation(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(TRESTLE_ATTESTATION_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored Trestle Attestation schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile Trestle Attestation schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored Gate Rule Registry 2.0.0 schema
pub fn validate_gate_rule_registry(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(GATE_RULE_REGISTRY_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored Gate Rule Registry schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile Gate Rule Registry schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate any JSON Value against the vendored PCrate Manifest 1.0.0 schema (ADR-0017 Option 1)
pub fn validate_pcrate_manifest(doc: &serde_json::Value) -> Result<(), Vec<String>> {
    let schema_val: serde_json::Value = serde_json::from_str(PCRATE_MANIFEST_SCHEMA_STR)
        .map_err(|e| vec![format!("Failed to parse vendored PCrate Manifest schema: {}", e)])?;
    let validator = jsonschema::validator_for(&schema_val)
        .map_err(|e| vec![format!("Failed to compile PCrate Manifest schema validator: {}", e)])?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("At '{}': {}", e.instance_path, e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Lookup default evidence tier for a canonical control ID from control-id-map.toml
pub fn lookup_control_default_tier(canonical_id: &str) -> Option<EvidenceTier> {
    #[derive(serde::Deserialize)]
    struct MapDef {
        #[serde(default)]
        default_tiers: std::collections::BTreeMap<String, String>,
    }
    let map: MapDef = toml::from_str(CONTROL_ID_MAP_STR).ok()?;
    let tier_str = map.default_tiers.get(canonical_id)?;
    match tier_str.as_str() {
        "static_check" => Some(EvidenceTier::StaticCheck),
        "test" => Some(EvidenceTier::Test),
        "symbolic" => Some(EvidenceTier::Symbolic),
        "formal_kernel" => Some(EvidenceTier::FormalKernel),
        _ => None,
    }
}

/// Resolve required evidence tier under explicit precedence hierarchy:
/// workspace_floor <= control_map_tier <= package_declared_tier <= cli_override
/// The floor wins if a package attempts to lower assurance below workspace floor or map tier.
pub fn resolve_required_tier(
    control_id: &str,
    package_declared_tier: Option<EvidenceTier>,
    workspace_floor: EvidenceTier,
    cli_override: Option<EvidenceTier>,
) -> EvidenceTier {
    let canonical = canonicalize_control_id(control_id);
    let map_tier = lookup_control_default_tier(&canonical);
    let mut resolved = workspace_floor;
    if let Some(mt) = map_tier {
        if mt > resolved {
            resolved = mt;
        }
    }
    if let Some(pkg_tier) = package_declared_tier {
        if pkg_tier > resolved {
            resolved = pkg_tier;
        }
    }
    if let Some(cli_tier) = cli_override {
        if cli_tier > resolved {
            resolved = cli_tier;
        }
    }
    resolved
}

/// Canonicalize human-readable control identifier (e.g. "SI-7(1)") into a NIST OSCAL NCName token (e.g. "si-7.1")
/// conforming to schema pattern `^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$`
/// Precedence Rule: Parenthesis-derived form wins; explicit '.'-form is treated as already-canonical and passed through.
pub fn canonicalize_control_id(raw: &str) -> String {
    let mut normalized = String::new();
    let trimmed = raw.trim();
    for ch in trimmed.chars() {
        if ch == '(' {
            normalized.push('.');
        } else if ch == ')' || ch == ' ' {
            // drop closing paren or space
        } else if ch.is_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            normalized.push(ch.to_ascii_lowercase());
        } else {
            normalized.push('_');
        }
    }
    if normalized.is_empty() || (!normalized.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')) {
        normalized = format!("ctrl_{}", normalized);
    }
    normalized
}

/// Reconstruct original human-readable control identifier from canonical token and OSCAL properties
pub fn reconstruct_original_control_id(canonical: &str, props: &[Property]) -> String {
    for prop in props {
        if prop.name == "raw-control-id" || prop.name == "control-id" {
            return prop.value.clone();
        }
    }
    canonical.to_string()
}

pub fn synthesize_compliance_bundle(inputs: &[SynthesisInput]) -> SynthesizedComplianceBundle {
    let now = Utc::now();
    let ap_uuid = Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"baseline:assessment-plan:prime-default");
    let ar_uuid = Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, format!("ar:{}", now.timestamp()).as_bytes());
    let poam_uuid = Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, format!("poam:{}", now.timestamp()).as_bytes());

    let mut observations = Vec::new();
    let mut findings = Vec::new();
    let mut poam_items = Vec::new();
    let mut suppressed_findings = Vec::new();

    let mut general_passed_count = 0;
    let mut tier_satisfied_count = 0;
    let mut risk_accepted_count = 0;

    for input in inputs {
        let obs_uuid = Uuid::new_v5(
            &PRIME_OSCAL_NAMESPACE,
            format!("obs:{}:{}", input.control_id, input.target_symbol).as_bytes(),
        );
        let find_uuid = Uuid::new_v5(
            &PRIME_OSCAL_NAMESPACE,
            format!("finding:{}:{}", input.control_id, input.target_symbol).as_bytes(),
        );

        let is_tier_satisfied = input.achieved_tier >= input.required_tier;
        let is_general_passed = input.kani_passed && !input.lean_sorry_detected;
        let is_satisfied = is_tier_satisfied && is_general_passed;

        if is_general_passed {
            general_passed_count += 1;
        }
        if is_satisfied {
            tier_satisfied_count += 1;
        }

        let (adjudicated_state, state_token, reason_token) = if is_satisfied {
            ("satisfied", "satisfied", "pass")
        } else if input.is_waived {
            match input.waiver_mode {
                gate_policy::GatePolicyConfigPolicyWaiverMode::RiskAccepted => {
                    risk_accepted_count += 1;
                    ("risk_accepted", "not-satisfied", "other")
                }
                gate_policy::GatePolicyConfigPolicyWaiverMode::Suppress => {
                    ("suppressed", "not-satisfied", "other")
                }
                gate_policy::GatePolicyConfigPolicyWaiverMode::Downgrade => {
                    ("unsatisfied", "not-satisfied", "fail")
                }
            }
        } else {
            ("unsatisfied", "not-satisfied", "fail")
        };

        observations.push(Observation {
            uuid: obs_uuid,
            title: format!("Verification Telemetry for {}", input.control_id),
            description: format!(
                "Assurance evaluation (Achieved: {}, Required: {}, Kani: {}, Lean 4 sorry: {}, Adjudicated: {}) for {}",
                input.achieved_tier,
                input.required_tier,
                if input.kani_passed { "PASS" } else { "FAIL" },
                input.lean_sorry_detected,
                adjudicated_state,
                input.target_symbol
            ),
            methods: vec!["TEST".to_string(), "FORMAL_VERIFICATION".to_string()],
            types: vec!["finding".to_string()],
            collected: now,
            subjects: vec![Subject {
                subject_uuid: Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, input.target_symbol.as_bytes()),
                r#type: "component".to_string(),
                title: input.component_title.clone(),
            }],
            props: vec![
                Property {
                    name: "control-id".to_string(),
                    value: input.control_id.clone(),
                    ns: None,
                },
                Property {
                    name: "required-evidence-tier".to_string(),
                    value: input.required_tier.to_string(),
                    ns: Some("https://prime.compliance/oscal/evidence-tier".to_string()),
                },
                Property {
                    name: "achieved-evidence-tier".to_string(),
                    value: input.achieved_tier.to_string(),
                    ns: Some("https://prime.compliance/oscal/evidence-tier".to_string()),
                },
                Property {
                    name: "tier-satisfied".to_string(),
                    value: is_tier_satisfied.to_string(),
                    ns: Some("https://prime.compliance/oscal/evidence-tier".to_string()),
                },
                Property {
                    name: "adjudicated-state".to_string(),
                    value: adjudicated_state.to_string(),
                    ns: Some("https://prime.compliance/oscal/adjudication".to_string()),
                },
                Property {
                    name: "lean4-axiom-sorry".to_string(),
                    value: input.lean_sorry_detected.to_string(),
                    ns: None,
                },
                Property {
                    name: "kani-pass".to_string(),
                    value: input.kani_passed.to_string(),
                    ns: None,
                },
            ],
        });

        if adjudicated_state == "suppressed" {
            suppressed_findings.push(SuppressedFindingItem {
                control_id: input.control_id.clone(),
                component: input.component_title.clone(),
                target_symbol: input.target_symbol.clone(),
                required_tier: input.required_tier.to_string(),
                achieved_tier: input.achieved_tier.to_string(),
                suppression_reason: input.failure_reason.clone().unwrap_or_else(|| "Suppressed by policy".to_string()),
                raw_telemetry: Some(format!("Kani: {}, Lean sorry: {}", input.kani_passed, input.lean_sorry_detected)),
            });
            continue;
        }

        findings.push(Finding {
            uuid: find_uuid,
            title: format!("Security Finding: Control {} ({})", input.control_id, input.component_title),
            implementation_statement_uuid: None,
            description: if is_satisfied {
                format!(
                    "Control {} satisfied: achieved tier '{}' meets required tier '{}'.",
                    input.control_id, input.achieved_tier, input.required_tier
                )
            } else if adjudicated_state == "risk_accepted" {
                format!(
                    "Control {} formally risk-accepted: achieved tier '{}', required tier '{}'. Formally tracked in POA&M.",
                    input.control_id, input.achieved_tier, input.required_tier
                )
            } else {
                format!(
                    "Control {} incomplete or tier mismatch: achieved '{}', required '{}'. Details: {}",
                    input.control_id,
                    input.achieved_tier,
                    input.required_tier,
                    input.failure_reason.as_deref().unwrap_or(if !is_tier_satisfied { "achieved tier below required" } else { "unproven obligations" })
                )
            },
            target: FindingTarget {
                r#type: "statement-id".to_string(),
                target_id: input.target_symbol.clone(),
                status: TargetStatus {
                    state: state_token.to_string(),
                    reason: Some(reason_token.to_string()),
                },
            },
            related_observations: vec![RelatedObservation {
                observation_uuid: obs_uuid,
            }],
            props: vec![
                Property {
                    name: "control-id".to_string(),
                    value: input.control_id.clone(),
                    ns: None,
                },
                Property {
                    name: "component".to_string(),
                    value: input.component_title.clone(),
                    ns: None,
                },
                Property {
                    name: "required-evidence-tier".to_string(),
                    value: input.required_tier.to_string(),
                    ns: Some("https://prime.compliance/oscal/evidence-tier".to_string()),
                },
                Property {
                    name: "achieved-evidence-tier".to_string(),
                    value: input.achieved_tier.to_string(),
                    ns: Some("https://prime.compliance/oscal/evidence-tier".to_string()),
                },
                Property {
                    name: "tier-satisfied".to_string(),
                    value: is_tier_satisfied.to_string(),
                    ns: Some("https://prime.compliance/oscal/evidence-tier".to_string()),
                },
                Property {
                    name: "adjudicated-state".to_string(),
                    value: adjudicated_state.to_string(),
                    ns: Some("https://prime.compliance/oscal/adjudication".to_string()),
                },
            ],
        });

        if !is_satisfied {
            let poam_item_uuid = Uuid::new_v5(
                &PRIME_OSCAL_NAMESPACE,
                format!("poam-item:{}:{}", input.control_id, input.target_symbol).as_bytes(),
            );
            if adjudicated_state == "risk_accepted" {
                poam_items.push(PoamItem {
                    uuid: poam_item_uuid,
                    title: format!("Risk Accepted Verification Obligation: Control {}", input.control_id),
                    description: format!(
                        "Target symbol '{}' waived under risk_accepted policy cap: {}",
                        input.target_symbol,
                        input.failure_reason.as_deref().unwrap_or("verification debt formally accepted")
                    ),
                    props: vec![
                        Property {
                            name: "severity".to_string(),
                            value: "moderate".to_string(),
                            ns: None,
                        },
                        Property {
                            name: "status".to_string(),
                            value: "risk-accepted".to_string(),
                            ns: None,
                        },
                        Property {
                            name: "control-id".to_string(),
                            value: input.control_id.clone(),
                            ns: None,
                        },
                        Property {
                            name: "target-date".to_string(),
                            value: (now + chrono::Duration::days(30)).to_rfc3339(),
                            ns: None,
                        },
                        Property {
                            name: "milestone-title".to_string(),
                            value: "Formal Proof Completion via Risk-Accepted POA&M".to_string(),
                            ns: None,
                        },
                    ],
                    related_findings: vec![RelatedFinding {
                        finding_uuid: find_uuid,
                    }],
                    related_observations: vec![RelatedObservation {
                        observation_uuid: obs_uuid,
                    }],
                    remarks: Some("Formally tracked POA&M milestone scheduled under approved risk acceptance cap.".to_string()),
                });
            } else {
                poam_items.push(PoamItem {
                    uuid: poam_item_uuid,
                    title: format!("Unresolved Verification Obligation: Control {}", input.control_id),
                    description: format!(
                        "Target symbol '{}' contains unproven formal obligations or test failures: {}",
                        input.target_symbol,
                        input.failure_reason.as_deref().unwrap_or("sorry axiom present")
                    ),
                    props: vec![
                        Property {
                            name: "severity".to_string(),
                            value: "critical".to_string(),
                            ns: None,
                        },
                        Property {
                            name: "status".to_string(),
                            value: "open".to_string(),
                            ns: None,
                        },
                        Property {
                            name: "control-id".to_string(),
                            value: input.control_id.clone(),
                            ns: None,
                        },
                        Property {
                            name: "target-date".to_string(),
                            value: (now + chrono::Duration::days(14)).to_rfc3339(),
                            ns: None,
                        },
                        Property {
                            name: "milestone-title".to_string(),
                            value: "Formal Proof Completion".to_string(),
                            ns: None,
                        },
                    ],
                    related_findings: vec![RelatedFinding {
                        finding_uuid: find_uuid,
                    }],
                    related_observations: vec![RelatedObservation {
                        observation_uuid: obs_uuid,
                    }],
                    remarks: Some("Formal Proof Completion: Discharge all sorry axioms in Lean 4 theorem and verify with zero axioms.".to_string()),
                });
            }
        }
    }

    let total = inputs.len().max(1) as f64;
    let decl_cov = general_passed_count as f64 / total;
    let tier_cov = tier_satisfied_count as f64 / total;
    let waiver_cov = (tier_satisfied_count + risk_accepted_count) as f64 / total;

    let has_unresolved_defects = poam_items.iter().any(|p| p.props.iter().any(|pr| pr.name == "status" && pr.value == "open"));
    let gate_status = if !has_unresolved_defects && tier_cov >= 1.0 {
        "passed"
    } else if !has_unresolved_defects && risk_accepted_count > 0 {
        "risk-accepted"
    } else {
        "rejected"
    };

    let coverage_props = vec![
        Property {
            name: "oscal-gate-status".to_string(),
            value: gate_status.to_string(),
            ns: Some("https://prime.compliance/oscal/gate".to_string()),
        },
        Property {
            name: "declaration-coverage".to_string(),
            value: format!("{:.4}", decl_cov),
            ns: Some("https://prime.compliance/oscal/coverage".to_string()),
        },
        Property {
            name: "tier-satisfied-coverage".to_string(),
            value: format!("{:.4}", tier_cov),
            ns: Some("https://prime.compliance/oscal/coverage".to_string()),
        },
        Property {
            name: "waiver-adjusted-coverage".to_string(),
            value: format!("{:.4}", waiver_cov),
            ns: Some("https://prime.compliance/oscal/coverage".to_string()),
        },
    ];

    let metadata = Metadata {
        title: "PRIME Continuous Authorization Assessment Results".to_string(),
        published: now,
        last_modified: now,
        version: "0.1.0".to_string(),
        oscal_version: "1.1.0".to_string(),
        props: coverage_props.clone(),
    };

    let ar_doc = OscalAssessmentResultsDocument {
        assessment_results: AssessmentResults {
            uuid: ar_uuid,
            metadata: metadata.clone(),
            import_ap: ImportAp {
                href: format!("urn:uuid:{}", ap_uuid),
            },
            results: vec![ResultItem {
                uuid: Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"result:default"),
                title: "Automated Dual Verification Execution".to_string(),
                description: "Evaluation pass executed by cargo-oscal".to_string(),
                start: now,
                end: now,
                props: coverage_props,
                reviewed_controls: ReviewedControls {
                    control_selections: vec![ControlSelection {
                        include_controls: inputs
                            .iter()
                            .map(|i| SelectControlById {
                                control_id: canonicalize_control_id(&i.control_id),
                            })
                            .collect(),
                    }],
                },
                observations,
                findings,
            }],
        },
    };

    let poam_doc = if poam_items.is_empty() {
        None
    } else {
        Some(OscalPoamDocument {
            plan_of_action_and_milestones: PlanOfActionAndMilestones {
                uuid: poam_uuid,
                metadata,
                poam_items,
            },
        })
    };

    let suppressed_doc = if suppressed_findings.is_empty() {
        None
    } else {
        Some(SuppressedFindingsDocument {
            uuid: Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, format!("suppressed:{}", now.timestamp()).as_bytes()),
            metadata: SuppressedFindingsMetadata {
                title: "PRIME Suppressed Security Findings Report".to_string(),
                published: now,
                version: "0.1.0".to_string(),
                oscal_version: "1.1.0".to_string(),
                policy_waiver_mode: "suppress".to_string(),
                total_suppressed: suppressed_findings.len(),
            },
            suppressed_findings,
        })
    };

    SynthesizedComplianceBundle {
        assessment_results: ar_doc,
        poam: poam_doc,
        suppressed_findings: suppressed_doc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_control_id_collision_precedence() {
        // Precedence Rule: Parenthesis-derived form "SI-7(1)" maps to "si-7.1"
        let paren_form = canonicalize_control_id("SI-7(1)");
        assert_eq!(paren_form, "si-7.1");

        // Explicit dotted form "SI-7.1" is treated as already canonical and maps to "si-7.1"
        let dotted_form = canonicalize_control_id("SI-7.1");
        assert_eq!(dotted_form, "si-7.1");

        // Both forms intentionally converge to the same NIST OSCAL token
        assert_eq!(paren_form, dotted_form);

        // Custom framework identifiers
        assert_eq!(canonicalize_control_id("CIS-1.1.1"), "cis-1.1.1");
        assert_eq!(canonicalize_control_id("ISO-A.8.1.2"), "iso-a.8.1.2");
        assert_eq!(canonicalize_control_id("AC-2"), "ac-2");
    }

    #[test]
    fn test_control_id_round_trip() {
        let original_label = "SI-7(1)";
        let canonical_token = canonicalize_control_id(original_label);
        assert_eq!(canonical_token, "si-7.1");

        let props = vec![Property {
            name: "raw-control-id".to_string(),
            value: original_label.to_string(),
            ns: None,
        }];

        let reconstructed = reconstruct_original_control_id(&canonical_token, &props);
        assert_eq!(reconstructed, original_label);
    }

    #[test]
    fn test_canonical_token_matches_oscal_token_schema() {
        // NIST OSCAL TokenDatatype pattern: ^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$
        let test_cases = [
            "SI-7(1)",
            "SI-7.1",
            "AC-2",
            "IA-5(2)(d)",
            "CIS-1.1.1",
            "ISO-A.8.1.2",
            "_CUSTOM-1",
        ];

        for raw in test_cases {
            let canonical = canonicalize_control_id(raw);
            assert!(
                canonical.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'),
                "Token '{}' must start with a letter or underscore",
                canonical
            );
            assert!(
                canonical.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'),
                "Token '{}' contains invalid NCName characters",
                canonical
            );
        }
    }

    #[test]
    fn test_resolve_required_tier_precedence() {
        // 1. Control map overrides workspace floor upward
        // si-7.1 has default_tier = formal_kernel
        let tier1 = resolve_required_tier("SI-7(1)", None, EvidenceTier::Test, None);
        assert_eq!(tier1, EvidenceTier::FormalKernel);

        // 2. Package cannot lower below floor (floor wins)
        let tier2 = resolve_required_tier("CM-7", Some(EvidenceTier::StaticCheck), EvidenceTier::Test, None);
        assert_eq!(tier2, EvidenceTier::Test);

        // 3. Package can raise above floor
        let tier3 = resolve_required_tier("AU-3", Some(EvidenceTier::Symbolic), EvidenceTier::Test, None);
        assert_eq!(tier3, EvidenceTier::Symbolic);

        // 4. CLI override takes highest precedence
        let tier4 = resolve_required_tier("CM-7", Some(EvidenceTier::StaticCheck), EvidenceTier::Test, Some(EvidenceTier::FormalKernel));
        assert_eq!(tier4, EvidenceTier::FormalKernel);
    }

    #[test]
    fn test_synthesize_bundle_coverage_props_and_validation() {
        let inputs = vec![
            SynthesisInput {
                title: "Test Input 1".to_string(),
                component_title: "Comp1".to_string(),
                control_id: "SI-7(1)".to_string(),
                target_symbol: "sym1".to_string(),
                required_tier: EvidenceTier::FormalKernel,
                achieved_tier: EvidenceTier::FormalKernel,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: gate_policy::GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
            SynthesisInput {
                title: "Test Input 2".to_string(),
                component_title: "Comp2".to_string(),
                control_id: "AU-3".to_string(),
                target_symbol: "sym2".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::StaticCheck,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: Some("unit test failed".to_string()),
                is_waived: true,
                waiver_mode: gate_policy::GatePolicyConfigPolicyWaiverMode::RiskAccepted,
            },
            SynthesisInput {
                title: "Test Input 3".to_string(),
                component_title: "Comp3".to_string(),
                control_id: "CM-7".to_string(),
                target_symbol: "sym3".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::StaticCheck,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: Some("Static check only; test tier required".to_string()),
                is_waived: true,
                waiver_mode: gate_policy::GatePolicyConfigPolicyWaiverMode::Suppress,
            },
        ];

        let bundle = synthesize_compliance_bundle(&inputs);
        assert!(bundle.validate().is_ok(), "Synthesized bundle must pass schema validation");

        let result = &bundle.assessment_results.assessment_results.results[0];
        let decl_prop = result.props.iter().find(|p| p.name == "declaration-coverage").expect("decl-coverage present");
        let tier_prop = result.props.iter().find(|p| p.name == "tier-satisfied-coverage").expect("tier-coverage present");
        let waiver_prop = result.props.iter().find(|p| p.name == "waiver-adjusted-coverage").expect("waiver-coverage present");

        assert_eq!(decl_prop.value, "1.0000"); // all 3 passed execution
        assert_eq!(tier_prop.value, "0.3333"); // 1/3 tier satisfied (sym1 only)
        assert_eq!(waiver_prop.value, "0.6667"); // 1 satisfied + 1 risk-accepted = 2/3 = 0.6667

        // Check suppressed findings emitted
        assert!(bundle.suppressed_findings.is_some());
        let supp_doc = bundle.suppressed_findings.unwrap();
        assert_eq!(supp_doc.suppressed_findings.len(), 1);
        assert_eq!(supp_doc.suppressed_findings[0].control_id, "CM-7");
    }
}
