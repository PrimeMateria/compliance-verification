//! Native Continuous Authorization Evidence Engine per Milestone 6 Simplification RFC
//! Defines the native `evidence.json` contract (11th schema), D1 Lean attestation, and D2 release status.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Top-level native continuous authorization evidence document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDocument {
    pub version: String,
    pub build: EvidenceBuild,
    pub policy: EvidencePolicy,
    pub components: Vec<EvidenceComponent>,
    pub controls: Vec<EvidenceControl>,
    pub waivers: Vec<EvidenceWaiver>,
    pub inheritance: Vec<EvidenceInheritance>,
    pub falsifiability: Vec<EvidenceFalsifiability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ast_agnosticism_pairs: Vec<EvidenceAgnosticismPair>,
    pub coverage: EvidenceCoverage,
    pub summary: EvidenceSummary,
}

/// Build environment and toolchain provenance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBuild {
    pub timestamp: String,
    pub git_sha: String,
    pub toolchains: BTreeMap<String, String>,
}

/// Active gate policy evaluation criteria
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidencePolicy {
    pub coverage_basis: String,
    pub min_control_coverage: f64,
    pub min_default_tier: String,
    pub waiver_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_accepted_max_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_accepted_max_fraction: Option<f64>,
}

/// Software component or external boundary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceComponent {
    pub id: String,
    pub title: String,
    pub source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

/// Control claim, assigned tier, and verification results
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceControl {
    pub id: String,
    pub component: String,
    pub kind: String,
    pub required_tier: String,
    pub achieved_tier: String,
    pub adjudicated_state: String,
    pub tier_satisfied: bool,
    pub evidence_sources: Vec<EvidenceSource>,
}

/// Concrete verification tool evidence record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSource {
    pub tool: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sorry_free: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Policy waiver record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceWaiver {
    pub control_id: String,
    pub mode: String,
    pub cap_count: u64,
    pub cap_fraction: f64,
    pub adjudication: String,
}

/// D4 CSP inheritance record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInheritance {
    pub key: String,
    pub source_id: String,
    pub controls: Vec<String>,
    pub attestation_sha256: String,
    pub attestation_expiry: String,
    pub is_active: bool,
}

/// D7 Falsifiability witness chain record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFalsifiability {
    pub control_id: String,
    pub witness_file: String,
    pub witness_sha256: String,
    pub verified: bool,
}
/// Static AST agnosticism witness pair record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAgnosticismPair {
    pub pair_id: String,
    pub ast_a_file: String,
    pub ast_a_hash: String,
    pub ast_b_file: String,
    pub ast_b_hash: String,
    pub shared_evidence_hash: String,
    pub verified: bool,
}

/// Coverage mathematics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCoverage {
    pub basis: String,
    pub numerator: u64,
    pub denominator: u64,
    pub percentage: f64,
    pub min_required: f64,
    pub passed: bool,
}

/// Executive gate summary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSummary {
    pub total_declarations: u64,
    pub unique_controls: u64,
    pub tier_satisfied: u64,
    pub risk_accepted: u64,
    pub unsatisfied: u64,
    pub coverage: f64,
    pub passed: bool,
}

// ============================================================================
// Deliverable D1: Formal Kernel Lean Attestation Document
// ============================================================================

/// D1: Cryptographic attestation artifact for formal kernel proof verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeanAttestationDocument {
    pub version: String,
    pub control_id: String,
    pub component: String,
    pub theorem_name: String,
    pub toolchain: LeanAttestationToolchain,
    pub proof_file: String,
    pub proof_sha256: String,
    pub sorry_free: bool,
    pub passed: bool,
    pub timestamp: String,
}

/// Lean / Lake toolchain information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeanAttestationToolchain {
    pub lean_version: String,
    pub lake_version: String,
}

/// Emits a D1 Lean attestation document
// The arguments are the document's fields in schema order; a parameter struct
// would only restate the document it constructs.
#[allow(clippy::too_many_arguments)]
pub fn create_lean_attestation(
    control_id: &str,
    component: &str,
    theorem_name: &str,
    proof_file: &str,
    proof_bytes: &[u8],
    sorry_free: bool,
    passed: bool,
    timestamp: &str,
    lean_version: &str,
    lake_version: &str,
) -> LeanAttestationDocument {
    let mut hasher = Sha256::new();
    hasher.update(proof_bytes);
    let proof_sha256 = format!("{:x}", hasher.finalize());

    LeanAttestationDocument {
        version: "1.0.0".to_string(),
        control_id: control_id.to_string(),
        component: component.to_string(),
        theorem_name: theorem_name.to_string(),
        toolchain: LeanAttestationToolchain {
            lean_version: lean_version.to_string(),
            lake_version: lake_version.to_string(),
        },
        proof_file: proof_file.to_string(),
        proof_sha256,
        sorry_free,
        passed,
        timestamp: timestamp.to_string(),
    }
}

// ============================================================================
// Deliverable D2: Release Status Document & Narrative Disclosures
// ============================================================================

/// D2: Release status artifact capturing narrative disclosures and boundary status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseStatusDocument {
    pub version: String,
    pub timestamp: String,
    pub git_sha: String,
    pub status: String,
    pub evidence_sha256: String,
    pub authorization_boundary: ReleaseAuthorizationBoundary,
    pub narrative_disclosures: Vec<NarrativeDisclosure>,
    pub summary: EvidenceSummary,
}

/// Authorization boundary metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAuthorizationBoundary {
    pub name: String,
    pub components: Vec<String>,
    pub inherited_sources: Vec<String>,
}

/// Narrative disclosure or boundary statement
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NarrativeDisclosure {
    pub section: String,
    pub boundary_entry: String,
    pub status: String,
}

pub type ReleaseStatus = ReleaseStatusDocument;

/// Emits a D2 release status document linking to the authoritative evidence hash
pub fn create_release_status(
    evidence: &EvidenceDocument,
    evidence_sha256: &str,
    timestamp: &str,
    git_sha: &str,
    boundary_name: &str,
    disclosures: Vec<NarrativeDisclosure>,
) -> ReleaseStatusDocument {
    let status = if !evidence.summary.passed {
        "rejected".to_string()
    } else if !disclosures.is_empty() {
        "incomplete".to_string()
    } else {
        "authorized".to_string()
    };

    let comp_names: Vec<String> = evidence
        .components
        .iter()
        .filter(|c| c.source_type == "workspace")
        .map(|c| c.title.clone())
        .collect();

    let inh_sources: Vec<String> = evidence
        .inheritance
        .iter()
        .map(|i| i.source_id.clone())
        .collect();

    ReleaseStatusDocument {
        version: "1.0.0".to_string(),
        timestamp: timestamp.to_string(),
        git_sha: git_sha.to_string(),
        status,
        evidence_sha256: evidence_sha256.to_string(),
        authorization_boundary: ReleaseAuthorizationBoundary {
            name: boundary_name.to_string(),
            components: comp_names,
            inherited_sources: inh_sources,
        },
        narrative_disclosures: disclosures,
        summary: evidence.summary.clone(),
    }
}

// ============================================================================
// Deliverable: Gate Decision Document
// ============================================================================

/// Gate decision artifact capturing the evaluation outcome, status, coverage, and boundaries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GateDecisionDocument {
    pub version: String,
    pub timestamp: String,
    pub git_sha: String,
    pub component_checks: String,
    pub release_acceptance: String,
    pub coverage_waiver_adjusted: f64,
    pub boundaries: Vec<String>,
    pub open_defect_codes: Vec<String>,
    pub violations: Vec<String>,
    pub evidence_sha256: String,
}

pub type GateDecision = GateDecisionDocument;

// The arguments are the document's fields in schema order; a parameter struct
// would only restate the document it constructs.
#[allow(clippy::too_many_arguments)]
pub fn create_gate_decision(
    timestamp: &str,
    git_sha: &str,
    component_checks: &str,
    release_acceptance: &str,
    coverage_waiver_adjusted: f64,
    boundaries: Vec<String>,
    open_defect_codes: Vec<String>,
    violations: Vec<String>,
    evidence_sha256: &str,
) -> GateDecisionDocument {
    GateDecisionDocument {
        version: "1.0.0".to_string(),
        timestamp: timestamp.to_string(),
        git_sha: git_sha.to_string(),
        component_checks: component_checks.to_string(),
        release_acceptance: release_acceptance.to_string(),
        coverage_waiver_adjusted,
        boundaries,
        open_defect_codes,
        violations,
        evidence_sha256: evidence_sha256.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate_evidence;

    fn sample_evidence() -> EvidenceDocument {
        let mut toolchains = BTreeMap::new();
        toolchains.insert("rustc".to_string(), "1.99.1".to_string());
        toolchains.insert("kani".to_string(), "0.68.0".to_string());
        toolchains.insert("lean".to_string(), "4.35.0".to_string());

        EvidenceDocument {
            version: "1.0.0".to_string(),
            build: EvidenceBuild {
                timestamp: "2026-11-12T00:00:00Z".to_string(),
                git_sha: "abcdef0123456789".to_string(),
                toolchains,
            },
            policy: EvidencePolicy {
                coverage_basis: "unique_controls".to_string(),
                min_control_coverage: 1.0,
                min_default_tier: "test".to_string(),
                waiver_mode: "downgrade".to_string(),
                risk_accepted_max_count: Some(1),
                risk_accepted_max_fraction: Some(0.20),
            },
            components: vec![
                EvidenceComponent {
                    id: "workspace-prime".to_string(),
                    title: "PRIME Core".to_string(),
                    source_type: "workspace".to_string(),
                    attestation_expiry: None,
                    is_active: None,
                },
                EvidenceComponent {
                    id: "csp-aws".to_string(),
                    title: "AWS GovCloud".to_string(),
                    source_type: "inherited".to_string(),
                    attestation_expiry: Some("2026-12-31T23:59:59Z".to_string()),
                    is_active: Some(true),
                },
            ],
            controls: vec![
                EvidenceControl {
                    id: "si-7".to_string(),
                    component: "PRIME Core".to_string(),
                    kind: "implements".to_string(),
                    required_tier: "formal_kernel".to_string(),
                    achieved_tier: "formal_kernel".to_string(),
                    adjudicated_state: "satisfied".to_string(),
                    tier_satisfied: true,
                    evidence_sources: vec![EvidenceSource {
                        tool: "lean".to_string(),
                        passed: true,
                        sorry_free: Some(true),
                        reason: None,
                        output_file: None,
                        sha256: None,
                    }],
                },
                EvidenceControl {
                    id: "pe-3".to_string(),
                    component: "AWS GovCloud".to_string(),
                    kind: "inherited".to_string(),
                    required_tier: "test".to_string(),
                    achieved_tier: "test".to_string(),
                    adjudicated_state: "satisfied".to_string(),
                    tier_satisfied: true,
                    evidence_sources: vec![],
                },
            ],
            waivers: vec![],
            inheritance: vec![EvidenceInheritance {
                key: "aws_govcloud".to_string(),
                source_id: "aws-govcloud-east".to_string(),
                controls: vec!["pe-3".to_string()],
                attestation_sha256:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                attestation_expiry: "2026-12-31T23:59:59Z".to_string(),
                is_active: true,
            }],
            falsifiability: vec![EvidenceFalsifiability {
                control_id: "si-7".to_string(),
                witness_file: "attestations/si-7.lean-attestation.json".to_string(),
                witness_sha256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
                verified: true,
            }],
            ast_agnosticism_pairs: vec![EvidenceAgnosticismPair {
                pair_id: "pair01_scalar_commutativity".to_string(),
                ast_a_file: "tests/fixtures/ast_pairs/pair01_scalar_commutativity_a.tex"
                    .to_string(),
                ast_a_hash:
                    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                        .to_string(),
                ast_b_file: "tests/fixtures/ast_pairs/pair01_scalar_commutativity_b.tex"
                    .to_string(),
                ast_b_hash:
                    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                        .to_string(),
                shared_evidence_hash:
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                verified: true,
            }],
            coverage: EvidenceCoverage {
                basis: "unique_controls".to_string(),
                numerator: 2,
                denominator: 2,
                percentage: 1.0,
                min_required: 1.0,
                passed: true,
            },
            summary: EvidenceSummary {
                total_declarations: 2,
                unique_controls: 2,
                tier_satisfied: 2,
                risk_accepted: 0,
                unsatisfied: 0,
                coverage: 1.0,
                passed: true,
            },
        }
    }

    #[test]
    fn test_evidence_document_validates_against_schema() {
        let doc = sample_evidence();
        let val = serde_json::to_value(&doc).unwrap();
        let res = validate_evidence(&val);
        assert!(res.is_ok(), "Validation errors: {:?}", res);
    }

    #[test]
    fn test_evidence_document_invalid_percentage_fails_validation() {
        let mut doc = sample_evidence();
        doc.coverage.percentage = 1.5; // Exceeds maximum 1.0
        let val = serde_json::to_value(&doc).unwrap();
        let res = validate_evidence(&val);
        assert!(res.is_err());
        let errs = res.unwrap_err();
        assert!(errs
            .iter()
            .any(|e| e.contains("is greater than the maximum")));
    }

    #[test]
    fn test_evidence_document_invalid_enum_fails_validation() {
        let mut doc = sample_evidence();
        doc.controls[0].kind = "not_a_valid_kind".to_string();
        let val = serde_json::to_value(&doc).unwrap();
        let res = validate_evidence(&val);
        assert!(res.is_err());
    }

    #[test]
    fn test_d1_lean_attestation_emission_and_hashing() {
        let proof_bytes = b"theorem prime_integrity : verified := by rfl";
        let att = create_lean_attestation(
            "si-7",
            "PRIME Core",
            "prime_integrity",
            "PrismPM/Integrity.lean",
            proof_bytes,
            true,
            true,
            "2026-11-12T00:00:00Z",
            "4.35.0",
            "5.0.0",
        );

        assert_eq!(att.control_id, "si-7");
        assert!(att.sorry_free);
        assert!(att.passed);

        let mut hasher = Sha256::new();
        hasher.update(proof_bytes);
        let expected_hash = format!("{:x}", hasher.finalize());
        assert_eq!(att.proof_sha256, expected_hash);
    }

    #[test]
    fn test_d2_release_status_emission_references_evidence_sha256() {
        let doc = sample_evidence();
        let evidence_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let rel = create_release_status(
            &doc,
            evidence_sha256,
            "2026-11-12T00:00:00Z",
            "abcdef0123456789",
            "PRIME Authorization Boundary",
            vec![NarrativeDisclosure {
                section: "system-characteristics.description".to_string(),
                boundary_entry: "PRIME continuous microkernel".to_string(),
                status: "disclosed".to_string(),
            }],
        );

        assert_eq!(rel.status, "incomplete");
        assert_eq!(rel.evidence_sha256, evidence_sha256);
        assert_eq!(
            rel.authorization_boundary.components,
            vec!["PRIME Core".to_string()]
        );
        assert_eq!(
            rel.authorization_boundary.inherited_sources,
            vec!["aws-govcloud-east".to_string()]
        );

        // When boundary disclosures are empty, status transitions to authorized
        let rel_authorized = create_release_status(
            &doc,
            evidence_sha256,
            "2026-11-12T00:00:00Z",
            "abcdef0123456789",
            "PRIME Authorization Boundary",
            vec![],
        );
        assert_eq!(rel_authorized.status, "authorized");
    }
}
