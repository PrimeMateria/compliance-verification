//! OSCAL Types - Schema-compliant NIST OSCAL 1.1.0 data structures
//! Covers Assessment Results (AR) and Plan of Action and Milestones (POA&M)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Top-level container for NIST OSCAL Assessment Results
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct OscalAssessmentResultsDocument {
    pub assessment_results: AssessmentResults,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct AssessmentResults {
    pub uuid: Uuid,
    pub metadata: Metadata,
    pub import_ap: ImportAp,
    pub results: Vec<ResultItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Metadata {
    pub title: String,
    pub published: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub version: String,
    pub oscal_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub props: Vec<Property>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct ImportAp {
    pub href: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct ResultItem {
    pub uuid: Uuid,
    pub title: String,
    pub description: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub props: Vec<Property>,
    pub reviewed_controls: ReviewedControls,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct ReviewedControls {
    pub control_selections: Vec<ControlSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct ControlSelection {
    pub include_controls: Vec<SelectControlById>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct SelectControlById {
    pub control_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Observation {
    pub uuid: Uuid,
    pub title: String,
    pub description: String,
    pub methods: Vec<String>,
    pub types: Vec<String>,
    pub collected: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<Subject>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub props: Vec<Property>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Subject {
    pub subject_uuid: Uuid,
    pub r#type: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Property {
    pub name: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ns: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Finding {
    pub uuid: Uuid,
    pub title: String,
    pub description: String,
    pub target: FindingTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_statement_uuid: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_observations: Vec<RelatedObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub props: Vec<Property>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct FindingTarget {
    pub r#type: String,
    pub target_id: String,
    pub status: TargetStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct TargetStatus {
    /// Expected values: "satisfied", "not-satisfied", or "other"
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct RelatedObservation {
    pub observation_uuid: Uuid,
}

/// Top-level container for NIST OSCAL Plan of Action and Milestones (POA&M)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct OscalPoamDocument {
    pub plan_of_action_and_milestones: PlanOfActionAndMilestones,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct PlanOfActionAndMilestones {
    pub uuid: Uuid,
    pub metadata: Metadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poam_items: Vec<PoamItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct PoamItem {
    pub uuid: Uuid,
    pub title: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub props: Vec<Property>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_findings: Vec<RelatedFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_observations: Vec<RelatedObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remarks: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct RelatedFinding {
    pub finding_uuid: Uuid,
}

/// Structured Kani CBMC verification telemetry exported via `-Z unstable-options --export-json`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KaniVerificationReport {
    pub verification_results: KaniResultsWrapper,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KaniResultsWrapper {
    pub summary: KaniSummary,
    #[serde(default)]
    pub results: Vec<KaniHarnessItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KaniSummary {
    pub total_harnesses: usize,
    pub executed: usize,
    pub successful: usize,
    pub failed: usize,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KaniHarnessItem {
    pub harness_id: String,
    pub status: String,
}

/// Structured Lean 4 compiler diagnostic exported via `lean --json`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LeanDiagnostic {
    pub file_name: String,
    pub severity: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
}

pub use inventory;

/// Registration structure collected at compile time via `inventory` (Option A)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalControlRegistration {
    pub control_id: &'static str,
    pub fn_name: &'static str,
    pub file: &'static str,
    pub line: u32,
}

inventory::collect!(OscalControlRegistration);

impl OscalControlRegistration {
    pub const fn new(
        control_id: &'static str,
        fn_name: &'static str,
        file: &'static str,
        line: u32,
    ) -> Self {
        Self {
            control_id,
            fn_name,
            file,
            line,
        }
    }
}

/// Cryptographically auditable document for suppressed security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct SuppressedFindingsDocument {
    pub uuid: Uuid,
    pub metadata: SuppressedFindingsMetadata,
    pub suppressed_findings: Vec<SuppressedFindingItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct SuppressedFindingsMetadata {
    pub title: String,
    pub published: DateTime<Utc>,
    pub version: String,
    pub oscal_version: String,
    pub policy_waiver_mode: String,
    pub total_suppressed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct SuppressedFindingItem {
    pub control_id: String,
    pub component: String,
    pub target_symbol: String,
    pub required_tier: String,
    pub achieved_tier: String,
    pub suppression_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_telemetry: Option<String>,
}

pub mod profile;
pub use profile::OscalProfileOscalProfileProfile;

// Ergonomic type aliases for OSCAL Profile types
pub type OscalProfile = profile::OscalProfileOscalProfileProfile;
pub type ProfileImport = profile::OscalProfileOscalProfileImport;
pub type ProfileModify = profile::OscalProfileOscalProfileModify;
pub type ProfileMerge = profile::OscalProfileOscalProfileMerge;
pub type ProfileSelectControlById = profile::OscalProfileOscalProfileSelectControlById;
pub type ParameterSetting = profile::ParameterSetting;

/// Top-level container for NIST OSCAL Profile
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct OscalProfileDocument {
    pub profile: OscalProfile,
}
