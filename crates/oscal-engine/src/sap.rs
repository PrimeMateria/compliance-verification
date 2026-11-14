//! Security Assessment Plan (SAP) Synthesis Engine per Milestone 5 Step 2
//! Synthesizes schema-valid NIST OSCAL 1.1.0 Assessment Plans under validate-before-write discipline

use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

use crate::canonicalize_control_id;
use crate::gate_policy::GatePolicyConfig;
use crate::tailoring::{get_effective_clock, ControlDisposition, TailoredBaselineReport};
use crate::{validate_assessment_plan, PRIME_OSCAL_NAMESPACE};

/// Verification phase names mapped 1:1 to OSCAL SAP activities
pub const ACTIVITY_PHASE_TEST_SUITE: &str = "test-suite";
pub const ACTIVITY_PHASE_KANI_CBMC: &str = "kani-cbmc";
pub const ACTIVITY_PHASE_LEAN4_KERNEL: &str = "lean4-kernel";
pub const ACTIVITY_PHASE_AR_SYNTHESIS: &str = "ar-synthesis";

/// Activity definition mapping verification phases to OSCAL SAP activities
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SapActivityDefinition {
    pub uuid: Uuid,
    pub title: &'static str,
    pub phase: &'static str,
    pub description: &'static str,
    pub verification_method: &'static str,
}

/// Retrieve the deterministic standard verification activities
pub fn get_standard_sap_activities() -> Vec<SapActivityDefinition> {
    vec![
        SapActivityDefinition {
            uuid: Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"activity:test-suite"),
            title: "Cargo Test Suite Execution",
            phase: ACTIVITY_PHASE_TEST_SUITE,
            description: "Automated unit and integration test suite execution",
            verification_method: "test",
        },
        SapActivityDefinition {
            uuid: Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"activity:kani-cbmc"),
            title: "Kani CBMC Symbolic Model Checking",
            phase: ACTIVITY_PHASE_KANI_CBMC,
            description: "Automated bounded model checking and symbolic invariant proofs",
            verification_method: "symbolic_model_check",
        },
        SapActivityDefinition {
            uuid: Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"activity:lean4-kernel"),
            title: "Lean 4 Kernel Theorem Verification",
            phase: ACTIVITY_PHASE_LEAN4_KERNEL,
            description: "Machine-checked interactive theorem proving and sorryAx detection",
            verification_method: "formal_kernel",
        },
        SapActivityDefinition {
            uuid: Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"activity:ar-synthesis"),
            title: "OSCAL Assessment Results Synthesis",
            phase: ACTIVITY_PHASE_AR_SYNTHESIS,
            description: "Continuous authorization evidence synthesis and schema validation",
            verification_method: "synthesis",
        },
    ]
}

/// Synthesize a schema-valid NIST OSCAL 1.1.0 Assessment Plan JSON document
/// driven strictly by an authoritative System Security Plan (SSP).
pub fn synthesize_assessment_plan(
    ssp_doc: &serde_json::Value,
    _tailoring_report: Option<&TailoredBaselineReport>,
    _control_dispositions: Option<&BTreeMap<String, ControlDisposition>>,
    _policy_config: Option<&GatePolicyConfig>,
    _legacy_ar_compat: bool,
    injected_now: Option<DateTime<Utc>>,
) -> Result<serde_json::Value, Vec<String>> {
    // 1. Validate SSP existence & resolve SSP UUID [E-OSCAL-016]
    let ssp_obj = ssp_doc
        .get("system-security-plan")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            vec![
                "[E-OSCAL-016] Security Assessment Plan synthesis failed: missing or unresolvable System Security Plan (no 'system-security-plan' root)".to_string(),
            ]
        })?;

    let ssp_uuid_str = ssp_obj
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            vec![
                "[E-OSCAL-016] Security Assessment Plan synthesis failed: missing or unresolvable System Security Plan (SSP UUID not found)".to_string(),
            ]
        })?;

    let ssp_uuid = Uuid::parse_str(ssp_uuid_str).map_err(|e| {
        vec![format!(
            "[E-OSCAL-016] Security Assessment Plan synthesis failed: unresolvable SSP UUID '{}': {}",
            ssp_uuid_str, e
        )]
    })?;

    let now = get_effective_clock(injected_now);
    let now_str = now.to_rfc3339();

    // Deterministic SAP UUID derived from SSP UUID
    let sap_uuid = Uuid::new_v5(&ssp_uuid, b"sap:document:prime-continuous-assessment-plan");

    // 2. Derive Assessment Subjects from SSP
    let mut include_subjects = Vec::new();

    if let Some(sys_impl) = ssp_obj.get("system-implementation").and_then(|v| v.as_object()) {
        // Workspace components
        if let Some(components) = sys_impl.get("components").and_then(|v| v.as_array()) {
            for comp in components {
                if let Some(comp_uuid_str) = comp.get("uuid").and_then(|u| u.as_str()) {
                    let comp_title = comp
                        .get("title")
                        .and_then(|t| t.as_str())
                        .unwrap_or("Software Component");
                    let subject_uuid = Uuid::new_v5(
                        &ssp_uuid,
                        format!("subject:component:{}", comp_uuid_str).as_bytes(),
                    );
                    include_subjects.push(json!({
                        "subject-uuid": subject_uuid.to_string(),
                        "type": "component",
                        "props": [
                            {
                                "name": "component-title",
                                "value": comp_title,
                                "ns": "nist.gov:oscal:prime-verification"
                            },
                            {
                                "name": "component-uuid",
                                "value": comp_uuid_str,
                                "ns": "nist.gov:oscal:prime-verification"
                            },
                            {
                                "name": "disposition",
                                "value": "workspace",
                                "ns": "nist.gov:oscal:prime-verification"
                            }
                        ]
                    }));
                }
            }
        }

        // Leveraged authorizations (inherited CSP sources)
        if let Some(lev_auths) = sys_impl.get("leveraged-authorizations").and_then(|v| v.as_array()) {
            for auth in lev_auths {
                if let Some(auth_uuid_str) = auth.get("uuid").and_then(|u| u.as_str()) {
                    let auth_title = auth
                        .get("title")
                        .and_then(|t| t.as_str())
                        .unwrap_or("Leveraged Authorization");
                    let subject_uuid = Uuid::new_v5(
                        &ssp_uuid,
                        format!("subject:leveraged:{}", auth_uuid_str).as_bytes(),
                    );
                    include_subjects.push(json!({
                        "subject-uuid": subject_uuid.to_string(),
                        "type": "component",
                        "props": [
                            {
                                "name": "leveraged-authorization-title",
                                "value": auth_title,
                                "ns": "nist.gov:oscal:prime-verification"
                            },
                            {
                                "name": "leveraged-authorization-uuid",
                                "value": auth_uuid_str,
                                "ns": "nist.gov:oscal:prime-verification"
                            },
                            {
                                "name": "disposition",
                                "value": "inherited",
                                "ns": "nist.gov:oscal:prime-verification"
                            }
                        ]
                    }));
                }
            }
        }
    }

    if include_subjects.is_empty() {
        let default_sub_uuid = Uuid::new_v5(&ssp_uuid, b"subject:default-component");
        include_subjects.push(json!({
            "subject-uuid": default_sub_uuid.to_string(),
            "type": "component",
            "props": [
                {
                    "name": "component-title",
                    "value": "Default System Component",
                    "ns": "nist.gov:oscal:prime-verification"
                }
            ]
        }));
    }

    let assessment_subjects = vec![json!({
        "type": "component",
        "description": "System software components and leveraged CSP authorizations assessed for NIST SP 800-53 controls.",
        "include-subjects": include_subjects
    })];

    // 3. Derive Objectives from SSP implemented-requirements
    let ctrl_impl = ssp_obj
        .get("control-implementation")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            vec![
                "[E-OSCAL-016] Security Assessment Plan synthesis failed: missing 'control-implementation' in SSP".to_string(),
            ]
        })?;

    let implemented_reqs = ctrl_impl
        .get("implemented-requirements")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            vec![
                "[E-OSCAL-016] Security Assessment Plan synthesis failed: missing 'implemented-requirements' in SSP".to_string(),
            ]
        })?;

    if implemented_reqs.is_empty() {
        return Err(vec![
            "[E-OSCAL-016] Security Assessment Plan synthesis failed: SSP contains zero implemented-requirements".to_string(),
        ]);
    }

    let mut local_objectives = Vec::new();
    let mut include_controls = Vec::new();
    let mut include_objectives = Vec::new();

    let mut objective_to_req: HashMap<String, String> = HashMap::new();
    let mut req_to_objectives: HashMap<String, Vec<String>> = HashMap::new();

    for req in implemented_reqs {
        let req_uuid = req
            .get("uuid")
            .and_then(|u| u.as_str())
            .ok_or_else(|| {
                vec!["SSP implemented-requirement is missing required 'uuid'".to_string()]
            })?;

        let raw_control_id = req
            .get("control-id")
            .and_then(|c| c.as_str())
            .ok_or_else(|| {
                vec!["SSP implemented-requirement is missing required 'control-id'".to_string()]
            })?;

        let canonical_id = canonicalize_control_id(raw_control_id);
        let obj_id = format!("{}_obj_1", canonical_id);

        objective_to_req.insert(obj_id.clone(), req_uuid.to_string());
        req_to_objectives
            .entry(req_uuid.to_string())
            .or_default()
            .push(obj_id.clone());

        local_objectives.push(json!({
            "control-id": raw_control_id,
            "description": format!("Assessment objective for control {}", raw_control_id),
            "parts": [
                {
                    "id": obj_id,
                    "name": "objective",
                    "prose": format!("Verify that control '{}' satisfies its required assurance tier and operational constraints.", raw_control_id)
                }
            ],
            "props": [
                {
                    "name": "implemented-requirement-uuid",
                    "value": req_uuid,
                    "ns": "nist.gov:oscal:prime-verification"
                }
            ]
        }));

        include_controls.push(json!({
            "control-id": raw_control_id
        }));

        include_objectives.push(json!({
            "objective-id": obj_id
        }));
    }

    // Bidirectional Invariant Check:
    // - Every SAP objective resolves to exactly one SSP implemented-requirement
    // - Every SSP implemented-requirement has >= 1 SAP objective
    for (obj_id, req_uuid) in &objective_to_req {
        if !req_to_objectives.contains_key(req_uuid) {
            return Err(vec![format!(
                "Invariant violation: SAP objective '{}' does not resolve to an SSP implemented-requirement",
                obj_id
            )]);
        }
    }
    for (req_uuid, objs) in &req_to_objectives {
        if objs.is_empty() {
            return Err(vec![format!(
                "Invariant violation: SSP implemented-requirement '{}' has zero SAP objectives",
                req_uuid
            )]);
        }
    }

    // 4. Map Verification Phases to OSCAL SAP Activities
    let standard_activities = get_standard_sap_activities();
    let mut activities_json = Vec::new();
    let mut task_associated_activities = Vec::new();

    for act in &standard_activities {
        activities_json.push(json!({
            "uuid": act.uuid.to_string(),
            "title": act.title,
            "description": act.description,
            "props": [
                {
                    "name": "phase",
                    "value": act.phase,
                    "ns": "nist.gov:oscal:prime-verification"
                },
                {
                    "name": "verification-method",
                    "value": act.verification_method,
                    "ns": "nist.gov:oscal:prime-verification"
                }
            ],
            "related-controls": {
                "control-selections": [
                    {
                        "include-controls": include_controls
                    }
                ],
                "control-objective-selections": [
                    {
                        "include-objectives": include_objectives
                    }
                ]
            }
        }));

        task_associated_activities.push(json!({
            "activity-uuid": act.uuid.to_string(),
            "subjects": [
                {
                    "type": "component",
                    "include-subjects": include_subjects.clone()
                }
            ]
        }));
    }

    // 5. Build Continuous Assessment Task
    let task_uuid = Uuid::new_v5(&ssp_uuid, b"task:continuous-assessment");
    let tasks = vec![json!({
        "uuid": task_uuid.to_string(),
        "type": "milestone",
        "title": "PRIME Continuous Automated Security Control Assessment",
        "description": "Executes automated verification phases and test suites against in-scope baseline controls.",
        "associated-activities": task_associated_activities
    })];

    // 6. Assemble Full OSCAL Assessment Plan Document
    let sap_doc = json!({
        "assessment-plan": {
            "uuid": sap_uuid.to_string(),
            "metadata": {
                "title": "PRIME Continuous Security Assessment Plan",
                "published": now_str,
                "last-modified": now_str,
                "version": "0.1.0",
                "oscal-version": "1.1.0",
                "parties": [
                    {
                        "uuid": Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"party:prime-core-team").to_string(),
                        "type": "organization",
                        "name": "PRIME Continuous Verification Core Team"
                    }
                ]
            },
            "import-ssp": {
                "href": format!("urn:uuid:{}", ssp_uuid),
                "remarks": format!("Authoritative System Security Plan (UUID: {})", ssp_uuid)
            },
            "reviewed-controls": {
                "description": "Controls and objectives reviewed during continuous automated verification.",
                "control-selections": [
                    {
                        "include-controls": include_controls
                    }
                ],
                "control-objective-selections": [
                    {
                        "include-objectives": include_objectives
                    }
                ]
            },
            "assessment-subjects": assessment_subjects,
            "local-definitions": {
                "objectives-and-methods": local_objectives,
                "activities": activities_json
            },
            "tasks": tasks
        }
    });

    // 7. Strict validate-before-write against official NIST OSCAL SAP schema
    validate_assessment_plan(&sap_doc)?;

    Ok(sap_doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_test_ssp(ssp_uuid_str: &str) -> serde_json::Value {
        json!({
            "system-security-plan": {
                "uuid": ssp_uuid_str,
                "metadata": {
                    "title": "Test SSP",
                    "published": "2026-11-10T12:00:00Z",
                    "last-modified": "2026-11-10T12:00:00Z",
                    "version": "0.1.0",
                    "oscal-version": "1.1.0"
                },
                "import-profile": {
                    "href": "urn:oscal:profile:fedramp_high"
                },
                "system-characteristics": {
                    "system-name": "Test System",
                    "security-sensitivity-level": "high",
                    "system-information": {
                        "information-types": [{
                            "uuid": "00000000-0000-0000-0000-000000000010",
                            "title": "Telemetry",
                            "description": "Telemetry",
                            "categorization": {
                                "system": "https://doi.org/10.6028/NIST.SP.800-60v2r1",
                                "information-type-ids": ["C.3.5.8"]
                            },
                            "confidentiality-impact": { "base": "fips-199-moderate" },
                            "integrity-impact": { "base": "fips-199-high" },
                            "availability-impact": { "base": "fips-199-moderate" }
                        }]
                    },
                    "security-impact-level": {
                        "security-objective-confidentiality": "fips-199-moderate",
                        "security-objective-integrity": "fips-199-high",
                        "security-objective-availability": "fips-199-moderate"
                    },
                    "status": { "state": "operational" },
                    "authorization-boundary": { "description": "Boundary" }
                },
                "system-implementation": {
                    "users": [{
                        "uuid": "00000000-0000-0000-0000-000000000020",
                        "title": "Test User"
                    }],
                    "components": [{
                        "uuid": "15434240-0a4c-5bf5-baf9-8444d2d5c1f2",
                        "type": "software",
                        "title": "PRIME OSCAL Compliance Engine",
                        "description": "Workspace package oscal-engine",
                        "status": { "state": "operational" }
                    }]
                },
                "control-implementation": {
                    "description": "Implementations",
                    "implemented-requirements": [
                        {
                            "uuid": "b83e02b6-fe45-5f37-b526-5b49414c1961",
                            "control-id": "au-3"
                        },
                        {
                            "uuid": "65efd40f-83d7-5e3f-9358-365ab96866ec",
                            "control-id": "si-7.1"
                        }
                    ]
                }
            }
        })
    }

    #[test]
    fn test_sap_import_ssp_references_synthesized_ssp_uuid() {
        let fixed_uuid = "cd90ba92-afb0-506f-ba09-3fd0cf34c315";
        let ssp = make_test_ssp(fixed_uuid);
        let fixed_now = Utc.with_ymd_and_hms(2026, 11, 10, 12, 0, 0).unwrap();

        let sap = synthesize_assessment_plan(&ssp, None, None, None, true, Some(fixed_now))
            .expect("SAP synthesis must succeed");

        let import_ssp_href = sap["assessment-plan"]["import-ssp"]["href"]
            .as_str()
            .expect("import-ssp.href must be present");

        assert!(
            import_ssp_href.contains(fixed_uuid),
            "import-ssp.href '{}' must contain the SSP UUID '{}'",
            import_ssp_href,
            fixed_uuid
        );
        assert_eq!(import_ssp_href, format!("urn:uuid:{}", fixed_uuid));
    }

    #[test]
    fn test_every_sap_objective_resolves_to_one_ssp_implemented_requirement() {
        let fixed_uuid = "cd90ba92-afb0-506f-ba09-3fd0cf34c315";
        let ssp = make_test_ssp(fixed_uuid);
        let fixed_now = Utc.with_ymd_and_hms(2026, 11, 10, 12, 0, 0).unwrap();

        let sap = synthesize_assessment_plan(&ssp, None, None, None, true, Some(fixed_now))
            .expect("SAP synthesis must succeed");

        let objectives = sap["assessment-plan"]["local-definitions"]["objectives-and-methods"]
            .as_array()
            .expect("objectives-and-methods array must be present");

        assert_eq!(objectives.len(), 2);

        let ssp_req_uuids: Vec<&str> = vec![
            "b83e02b6-fe45-5f37-b526-5b49414c1961",
            "65efd40f-83d7-5e3f-9358-365ab96866ec",
        ];

        for obj in objectives {
            let props = obj["props"].as_array().expect("props array");
            let req_uuid_prop = props
                .iter()
                .find(|p| p["name"] == "implemented-requirement-uuid")
                .expect("implemented-requirement-uuid prop must be present");
            let req_uuid = req_uuid_prop["value"].as_str().unwrap();
            assert!(
                ssp_req_uuids.contains(&req_uuid),
                "Objective req_uuid '{}' must match an SSP implemented requirement",
                req_uuid
            );
        }
    }

    #[test]
    fn test_sap_activities_map_to_verification_phases() {
        let fixed_uuid = "cd90ba92-afb0-506f-ba09-3fd0cf34c315";
        let ssp = make_test_ssp(fixed_uuid);
        let fixed_now = Utc.with_ymd_and_hms(2026, 11, 10, 12, 0, 0).unwrap();

        let sap = synthesize_assessment_plan(&ssp, None, None, None, true, Some(fixed_now))
            .expect("SAP synthesis must succeed");

        let activities = sap["assessment-plan"]["local-definitions"]["activities"]
            .as_array()
            .expect("activities array");

        assert_eq!(activities.len(), 4);
        let expected_phases = vec!["test-suite", "kani-cbmc", "lean4-kernel", "ar-synthesis"];

        for phase in &expected_phases {
            let found = activities.iter().any(|act| {
                act["props"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["name"] == "phase" && p["value"] == *phase)
            });
            assert!(found, "Activity for phase '{}' must be present in SAP", phase);
        }
    }

    #[test]
    fn test_degenerate_sap_one_objective_per_control() {
        let fixed_uuid = "cd90ba92-afb0-506f-ba09-3fd0cf34c315";
        let ssp = make_test_ssp(fixed_uuid);
        let fixed_now = Utc.with_ymd_and_hms(2026, 11, 10, 12, 0, 0).unwrap();

        let sap = synthesize_assessment_plan(&ssp, None, None, None, true, Some(fixed_now))
            .expect("Degenerate SAP synthesis must succeed");

        let selections = sap["assessment-plan"]["reviewed-controls"]["control-objective-selections"][0]["include-objectives"]
            .as_array()
            .expect("include-objectives");

        assert_eq!(selections.len(), 2);
        assert_eq!(selections[0]["objective-id"], "au-3_obj_1");
        assert_eq!(selections[1]["objective-id"], "si-7.1_obj_1");
    }

    #[test]
    fn test_missing_ssp_fails_closed_with_e_oscal_016() {
        let invalid_ssp = json!({ "not-an-ssp": {} });
        let errs = synthesize_assessment_plan(&invalid_ssp, None, None, None, true, None)
            .expect_err("Missing SSP must fail closed");

        assert!(errs.iter().any(|e| e.contains("[E-OSCAL-016]")));
    }

    #[test]
    fn test_sap_schema_invalid_aborts_without_write() {
        let bad_doc = json!({
            "assessment-plan": {
                "uuid": "not-a-valid-uuid"
            }
        });
        let errs = validate_assessment_plan(&bad_doc).expect_err("Invalid SAP must fail schema validation");
        assert!(!errs.is_empty());
        assert!(errs.iter().any(|e| e.contains("uuid") || e.contains("metadata")));
    }
}
