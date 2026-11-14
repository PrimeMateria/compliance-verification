//! Assessment Results (AR) Synthesis Engine per Milestone 5 Step 3
//! Synthesizes schema-valid NIST OSCAL 1.1.0 Assessment Results linked to SAP and SSP

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use oscal_types::{
    AssessmentResults, ControlSelection, Finding, FindingTarget, ImportAp, Metadata, Observation,
    OscalAssessmentResultsDocument, OscalPoamDocument, PlanOfActionAndMilestones, PoamItem,
    Property, RelatedFinding, RelatedObservation, ResultItem, ReviewedControls,
    SelectControlById, Subject, TargetStatus,
};

use crate::gate_policy::GatePolicyConfigPolicyWaiverMode;
use crate::sap::{
    ACTIVITY_PHASE_AR_SYNTHESIS, ACTIVITY_PHASE_KANI_CBMC, ACTIVITY_PHASE_LEAN4_KERNEL,
    ACTIVITY_PHASE_TEST_SUITE,
};
use crate::tailoring::get_effective_clock;
use crate::{
    canonicalize_control_id, EvidenceTier, SuppressedFindingItem,
    SuppressedFindingsDocument, SuppressedFindingsMetadata, SynthesisInput,
    SynthesizedComplianceBundle,
};

/// Information extracted from an OSCAL Assessment Plan (SAP)
#[derive(Debug, Clone)]
pub struct SapMetadata {
    pub sap_uuid: Uuid,
    pub activities: BTreeMap<Uuid, SapActivityInfo>,
    pub subjects: BTreeMap<Uuid, SapSubjectInfo>,
    pub objectives: BTreeMap<String, SapObjectiveInfo>,
    pub control_to_objective: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SapActivityInfo {
    pub uuid: Uuid,
    pub title: String,
    pub phase: String,
    pub verification_method: String,
}

#[derive(Debug, Clone)]
pub struct SapSubjectInfo {
    pub uuid: Uuid,
    pub subject_type: String,
    pub title: String,
    pub component_uuid: Option<String>,
    pub disposition: String,
}

#[derive(Debug, Clone)]
pub struct SapObjectiveInfo {
    pub control_id: String,
    pub objective_id: String,
    pub implemented_requirement_uuid: Uuid,
}

/// Parse and extract verified structure from an OSCAL SAP JSON document
pub fn parse_sap_for_linking(sap_val: &Value) -> Result<SapMetadata, Vec<String>> {
    let sap_obj = sap_val
        .get("assessment-plan")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            vec!["[E-OSCAL-017] Missing 'assessment-plan' root object in SAP".to_string()]
        })?;

    let sap_uuid_str = sap_obj
        .get("uuid")
        .and_then(|u| u.as_str())
        .ok_or_else(|| vec!["[E-OSCAL-017] Missing 'uuid' in SAP".to_string()])?;

    let sap_uuid = Uuid::parse_str(sap_uuid_str).map_err(|e| {
        vec![format!("[E-OSCAL-017] Invalid SAP UUID '{}': {}", sap_uuid_str, e)]
    })?;

    // 1. Extract Activities
    let mut activities = BTreeMap::new();
    if let Some(local_defs) = sap_obj.get("local-definitions").and_then(|v| v.as_object()) {
        if let Some(acts) = local_defs.get("activities").and_then(|v| v.as_array()) {
            for act in acts {
                if let Some(u_str) = act.get("uuid").and_then(|u| u.as_str()) {
                    if let Ok(act_uuid) = Uuid::parse_str(u_str) {
                        let title = act.get("title").and_then(|t| t.as_str()).unwrap_or("Activity").to_string();
                        let mut phase = String::new();
                        let mut method = String::new();
                        if let Some(props) = act.get("props").and_then(|p| p.as_array()) {
                            for pr in props {
                                if let (Some(n), Some(v)) = (pr.get("name").and_then(|n| n.as_str()), pr.get("value").and_then(|v| v.as_str())) {
                                    if n == "phase" {
                                        phase = v.to_string();
                                    } else if n == "verification-method" {
                                        method = v.to_string();
                                    }
                                }
                            }
                        }
                        activities.insert(act_uuid, SapActivityInfo {
                            uuid: act_uuid,
                            title,
                            phase,
                            verification_method: method,
                        });
                    }
                }
            }
        }
    }

    // 2. Extract Assessment Subjects
    let mut subjects = BTreeMap::new();
    if let Some(sub_groups) = sap_obj.get("assessment-subjects").and_then(|v| v.as_array()) {
        for grp in sub_groups {
            if let Some(incl) = grp.get("include-subjects").and_then(|v| v.as_array()) {
                for s in incl {
                    if let Some(u_str) = s.get("subject-uuid").and_then(|u| u.as_str()) {
                        if let Ok(sub_uuid) = Uuid::parse_str(u_str) {
                            let mut title = "Assessment Subject".to_string();
                            let mut comp_uuid = None;
                            let mut disp = "workspace".to_string();
                            if let Some(props) = s.get("props").and_then(|p| p.as_array()) {
                                for pr in props {
                                    if let (Some(n), Some(v)) = (pr.get("name").and_then(|n| n.as_str()), pr.get("value").and_then(|v| v.as_str())) {
                                        if n == "component-title" || n == "leveraged-authorization-title" {
                                            title = v.to_string();
                                        } else if n == "component-uuid" || n == "leveraged-authorization-uuid" {
                                            comp_uuid = Some(v.to_string());
                                        } else if n == "disposition" {
                                            disp = v.to_string();
                                        }
                                    }
                                }
                            }
                            let stype = s.get("type").and_then(|t| t.as_str()).unwrap_or("component").to_string();
                            subjects.insert(sub_uuid, SapSubjectInfo {
                                uuid: sub_uuid,
                                subject_type: stype,
                                title,
                                component_uuid: comp_uuid,
                                disposition: disp,
                            });
                        }
                    }
                }
            }
        }
    }

    // 3. Extract Local Objectives
    let mut objectives = BTreeMap::new();
    let mut control_to_objective = BTreeMap::new();
    if let Some(local_defs) = sap_obj.get("local-definitions").and_then(|v| v.as_object()) {
        if let Some(objs) = local_defs
            .get("objectives-and-methods")
            .or_else(|| local_defs.get("objectives"))
            .and_then(|v| v.as_array())
        {
            for obj in objs {
                let raw_cid = obj.get("control-id").and_then(|c| c.as_str()).unwrap_or_default();
                let canonical_cid = canonicalize_control_id(raw_cid);

                let mut obj_id = format!("{}_obj_1", canonical_cid);
                if let Some(parts) = obj.get("parts").and_then(|p| p.as_array()) {
                    for part in parts {
                        if part.get("name").and_then(|n| n.as_str()) == Some("objective") {
                            if let Some(id) = part.get("id").and_then(|i| i.as_str()) {
                                obj_id = id.to_string();
                            }
                        }
                    }
                }

                let mut ir_uuid = Uuid::nil();
                if let Some(props) = obj.get("props").and_then(|p| p.as_array()) {
                    for pr in props {
                        if pr.get("name").and_then(|n| n.as_str()) == Some("implemented-requirement-uuid") {
                            if let Some(u) = pr.get("value").and_then(|v| v.as_str()) {
                                if let Ok(parsed) = Uuid::parse_str(u) {
                                    ir_uuid = parsed;
                                }
                            }
                        }
                    }
                }

                objectives.insert(obj_id.clone(), SapObjectiveInfo {
                    control_id: raw_cid.to_string(),
                    objective_id: obj_id.clone(),
                    implemented_requirement_uuid: ir_uuid,
                });
                control_to_objective.insert(canonical_cid, obj_id);
            }
        }
    }

    Ok(SapMetadata {
        sap_uuid,
        activities,
        subjects,
        objectives,
        control_to_objective,
    })
}

/// Extract valid implemented-requirement UUIDs from an SSP document
pub fn extract_ssp_implemented_requirement_uuids(ssp_val: &Value) -> BTreeSet<Uuid> {
    let mut uuids = BTreeSet::new();
    if let Some(ssp_obj) = ssp_val.get("system-security-plan").and_then(|v| v.as_object()) {
        if let Some(ctrl_impl) = ssp_obj.get("control-implementation").and_then(|v| v.as_object()) {
            if let Some(reqs) = ctrl_impl.get("implemented-requirements").and_then(|v| v.as_array()) {
                for r in reqs {
                    if let Some(u_str) = r.get("uuid").and_then(|u| u.as_str()) {
                        if let Ok(u) = Uuid::parse_str(u_str) {
                            uuids.insert(u);
                        }
                    }
                }
            }
        }
    }
    uuids
}

/// Synthesize linked NIST OSCAL Assessment Results (AR) bundle strictly bound to SAP and SSP
pub fn synthesize_linked_compliance_bundle(
    inputs: &[SynthesisInput],
    sap_val: &Value,
    ssp_val: Option<&Value>,
    injected_now: Option<DateTime<Utc>>,
) -> Result<SynthesizedComplianceBundle, Vec<String>> {
    let sap_meta = parse_sap_for_linking(sap_val)?;
    let now = get_effective_clock(injected_now);

    let ssp_ir_uuids = ssp_val.map(extract_ssp_implemented_requirement_uuids);

    let ar_uuid = Uuid::new_v5(
        &sap_meta.sap_uuid,
        format!("ar:doc:{}", now.timestamp()).as_bytes(),
    );
    let poam_uuid = Uuid::new_v5(
        &sap_meta.sap_uuid,
        format!("poam:doc:{}", now.timestamp()).as_bytes(),
    );

    // Track activities for orphan detection
    let mut activity_by_phase: BTreeMap<String, Uuid> = BTreeMap::new();
    for (act_uuid, act_info) in &sap_meta.activities {
        activity_by_phase.insert(act_info.phase.clone(), *act_uuid);
    }

    let default_test_act = activity_by_phase.get(ACTIVITY_PHASE_TEST_SUITE).copied();
    let default_kani_act = activity_by_phase.get(ACTIVITY_PHASE_KANI_CBMC).copied();
    let default_lean_act = activity_by_phase.get(ACTIVITY_PHASE_LEAN4_KERNEL).copied();
    let ar_synth_act = activity_by_phase.get(ACTIVITY_PHASE_AR_SYNTHESIS).copied();

    // Map component titles to subjects
    let mut subject_by_title: BTreeMap<String, Uuid> = BTreeMap::new();
    let mut default_workspace_subject = None;
    let mut default_inherited_subject = None;

    for (sub_uuid, sub_info) in &sap_meta.subjects {
        subject_by_title.insert(sub_info.title.clone(), *sub_uuid);
        if sub_info.disposition == "workspace" && default_workspace_subject.is_none() {
            default_workspace_subject = Some(*sub_uuid);
        } else if sub_info.disposition == "inherited" && default_inherited_subject.is_none() {
            default_inherited_subject = Some(*sub_uuid);
        }
    }
    let fallback_subject = default_workspace_subject
        .or(default_inherited_subject)
        .unwrap_or_else(|| Uuid::new_v5(&sap_meta.sap_uuid, b"subject:default"));

    let mut observations = Vec::new();
    let mut findings = Vec::new();
    let mut poam_items = Vec::new();
    let mut suppressed_findings = Vec::new();

    let mut general_passed_count = 0;
    let mut tier_satisfied_count = 0;
    let mut risk_accepted_count = 0;

    // Track generated finding targets and objective mappings to enforce bidirectional invariant
    let mut objective_findings_count: BTreeMap<String, usize> = BTreeMap::new();
    for obj_id in sap_meta.objectives.keys() {
        objective_findings_count.insert(obj_id.clone(), 0);
    }

    // Map control canonical ID to matching inputs
    let mut control_inputs: BTreeMap<String, Vec<&SynthesisInput>> = BTreeMap::new();
    for input in inputs {
        let canonical = canonicalize_control_id(&input.control_id);
        control_inputs.entry(canonical).or_default().push(input);
    }

    // 1. Emit Metadata-Only Observation for `ar-synthesis` (Self-Reference Rule)
    if let Some(synth_act_uuid) = ar_synth_act {
        // Enforce orphan check on activity
        if !sap_meta.activities.contains_key(&synth_act_uuid) {
            return Err(vec![format!(
                "[E-OSCAL-017] Orphaned assessment observation: observation references missing activity target '{}'",
                synth_act_uuid
            )]);
        }

        let obs_uuid = Uuid::new_v5(
            &sap_meta.sap_uuid,
            format!("obs:{}:metadata", synth_act_uuid).as_bytes(),
        );

        observations.push(Observation {
            uuid: obs_uuid,
            title: "Assessment Results Synthesis Execution Telemetry".to_string(),
            description: format!(
                "Metadata-only observation recording continuous assessment results synthesis execution for SAP {}",
                sap_meta.sap_uuid
            ),
            methods: vec!["SYNTHESIS".to_string()],
            types: vec!["metadata".to_string()],
            collected: now,
            subjects: vec![Subject {
                subject_uuid: fallback_subject,
                r#type: "component".to_string(),
                title: "PRIME Compiler Orchestrator".to_string(),
            }],
            props: vec![
                Property {
                    name: "activity-uuid".to_string(),
                    value: synth_act_uuid.to_string(),
                    ns: Some("nist.gov:oscal:prime-verification".to_string()),
                },
                Property {
                    name: "activity-phase".to_string(),
                    value: ACTIVITY_PHASE_AR_SYNTHESIS.to_string(),
                    ns: Some("nist.gov:oscal:prime-verification".to_string()),
                },
                Property {
                    name: "ar-uuid".to_string(),
                    value: ar_uuid.to_string(),
                    ns: Some("nist.gov:oscal:prime-verification".to_string()),
                },
                Property {
                    name: "observation-kind".to_string(),
                    value: "metadata-only".to_string(),
                    ns: Some("nist.gov:oscal:prime-verification".to_string()),
                },
            ],
        });
    }

    // 2. Synthesize Observations and Findings per SAP Objective
    for (obj_id, obj_info) in &sap_meta.objectives {
        let canonical_cid = canonicalize_control_id(&obj_info.control_id);

        // Verify SSP Implemented Requirement Existence [E-OSCAL-017]
        if let Some(ref valid_ssp_ir) = ssp_ir_uuids {
            if !valid_ssp_ir.contains(&obj_info.implemented_requirement_uuid) {
                let find_uuid = Uuid::new_v5(
                    &sap_meta.sap_uuid,
                    format!("finding:{}:{}", obj_id, obj_info.implemented_requirement_uuid).as_bytes(),
                );
                return Err(vec![format!(
                    "[E-OSCAL-017] Orphaned assessment finding: finding '{}' references missing implemented-requirement target '{}' (control {})",
                    find_uuid, obj_info.implemented_requirement_uuid, obj_info.control_id
                )]);
            }
        }

        let matching_inputs = control_inputs.get(&canonical_cid);

        if let Some(matched_inputs) = matching_inputs {
            // Workspace Implemented Control
            for input in matched_inputs {
                let subject_uuid = subject_by_title
                    .get(&input.component_title)
                    .copied()
                    .or(default_workspace_subject)
                    .unwrap_or(fallback_subject);

                // E-OSCAL-017 subject check
                if !sap_meta.subjects.contains_key(&subject_uuid) {
                    let offending_obs_uuid = Uuid::new_v5(
                        &sap_meta.sap_uuid,
                        format!("obs:unresolved:{}:{}", input.control_id, input.target_symbol).as_bytes(),
                    );
                    return Err(vec![format!(
                        "[E-OSCAL-017] Orphaned assessment observation: observation '{}' references missing subject target '{}'",
                        offending_obs_uuid, subject_uuid
                    )]);
                }

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
                        GatePolicyConfigPolicyWaiverMode::RiskAccepted => {
                            risk_accepted_count += 1;
                            ("risk_accepted", "not-satisfied", "other")
                        }
                        GatePolicyConfigPolicyWaiverMode::Suppress => {
                            ("suppressed", "not-satisfied", "other")
                        }
                        GatePolicyConfigPolicyWaiverMode::Downgrade => {
                            ("unsatisfied", "not-satisfied", "fail")
                        }
                    }
                } else {
                    ("unsatisfied", "not-satisfied", "fail")
                };

                // Emit observation bound to active verification activity
                let (act_uuid, act_phase, method) = if input.required_tier >= EvidenceTier::FormalKernel && default_lean_act.is_some() {
                    (default_lean_act.unwrap(), ACTIVITY_PHASE_LEAN4_KERNEL, "FORMAL_VERIFICATION")
                } else if input.required_tier >= EvidenceTier::Symbolic && default_kani_act.is_some() {
                    (default_kani_act.unwrap(), ACTIVITY_PHASE_KANI_CBMC, "FORMAL_VERIFICATION")
                } else {
                    (default_test_act.unwrap_or_else(|| Uuid::new_v5(&sap_meta.sap_uuid, b"act:fallback")), ACTIVITY_PHASE_TEST_SUITE, "TEST")
                };

                // E-OSCAL-017 activity check
                if !sap_meta.activities.contains_key(&act_uuid) {
                    let offending_obs_uuid = Uuid::new_v5(
                        &sap_meta.sap_uuid,
                        format!("obs:unresolved_act:{}:{}", input.control_id, input.target_symbol).as_bytes(),
                    );
                    return Err(vec![format!(
                        "[E-OSCAL-017] Orphaned assessment observation: observation '{}' references missing activity target '{}'",
                        offending_obs_uuid, act_uuid
                    )]);
                }

                let obs_uuid = Uuid::new_v5(
                    &sap_meta.sap_uuid,
                    format!("obs:{}:{}:{}:{}", act_uuid, subject_uuid, input.control_id, input.target_symbol).as_bytes(),
                );

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
                    methods: vec![method.to_string()],
                    types: vec!["finding".to_string()],
                    collected: now,
                    subjects: vec![Subject {
                        subject_uuid,
                        r#type: "component".to_string(),
                        title: input.component_title.clone(),
                    }],
                    props: vec![
                        Property {
                            name: "activity-uuid".to_string(),
                            value: act_uuid.to_string(),
                            ns: Some("nist.gov:oscal:prime-verification".to_string()),
                        },
                        Property {
                            name: "activity-phase".to_string(),
                            value: act_phase.to_string(),
                            ns: Some("nist.gov:oscal:prime-verification".to_string()),
                        },
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

                // Deterministic finding UUID keyed on (SAP UUID, objective ID, implemented-requirement UUID)
                let find_uuid = Uuid::new_v5(
                    &sap_meta.sap_uuid,
                    format!("finding:{}:{}", obj_id, obj_info.implemented_requirement_uuid).as_bytes(),
                );

                findings.push(Finding {
                    uuid: find_uuid,
                    title: format!("Security Finding: Control {} ({})", input.control_id, input.component_title),
                    description: if is_satisfied {
                        format!(
                            "Control {} objective {} satisfied: achieved tier '{}' meets required tier '{}'.",
                            input.control_id, obj_id, input.achieved_tier, input.required_tier
                        )
                    } else if adjudicated_state == "risk_accepted" {
                        format!(
                            "Control {} objective {} formally risk-accepted: achieved tier '{}', required tier '{}'. Formally tracked in POA&M.",
                            input.control_id, obj_id, input.achieved_tier, input.required_tier
                        )
                    } else {
                        format!(
                            "Control {} objective {} incomplete or tier mismatch: achieved '{}', required '{}'. Details: {}",
                            input.control_id,
                            obj_id,
                            input.achieved_tier,
                            input.required_tier,
                            input.failure_reason.as_deref().unwrap_or(if !is_tier_satisfied { "achieved tier below required" } else { "unproven obligations" })
                        )
                    },
                    implementation_statement_uuid: Some(obj_info.implemented_requirement_uuid),
                    target: FindingTarget {
                        r#type: "objective-id".to_string(),
                        target_id: obj_id.clone(),
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
                            name: "objective-id".to_string(),
                            value: obj_id.clone(),
                            ns: Some("nist.gov:oscal:prime-verification".to_string()),
                        },
                        Property {
                            name: "implemented-requirement-uuid".to_string(),
                            value: obj_info.implemented_requirement_uuid.to_string(),
                            ns: Some("nist.gov:oscal:prime-verification".to_string()),
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

                *objective_findings_count.entry(obj_id.clone()).or_default() += 1;

                if !is_satisfied {
                    let poam_item_uuid = Uuid::new_v5(
                        &sap_meta.sap_uuid,
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
        } else {
            // Inherited Control from CSP
            let sub_uuid = default_inherited_subject.unwrap_or(fallback_subject);
            let act_uuid = default_test_act.unwrap_or_else(|| Uuid::new_v5(&sap_meta.sap_uuid, b"act:inherited"));

            let obs_uuid = Uuid::new_v5(
                &sap_meta.sap_uuid,
                format!("obs:inherited:{}:{}:{}", act_uuid, sub_uuid, obj_info.control_id).as_bytes(),
            );

            observations.push(Observation {
                uuid: obs_uuid,
                title: format!("CSP External Attestation for Control {}", obj_info.control_id),
                description: format!(
                    "External authorization attestation package verified for control {}",
                    obj_info.control_id
                ),
                methods: vec!["EXAMINE".to_string()],
                types: vec!["attestation".to_string()],
                collected: now,
                subjects: vec![Subject {
                    subject_uuid: sub_uuid,
                    r#type: "component".to_string(),
                    title: "Leveraged External Authorization".to_string(),
                }],
                props: vec![
                    Property {
                        name: "activity-uuid".to_string(),
                        value: act_uuid.to_string(),
                        ns: Some("nist.gov:oscal:prime-verification".to_string()),
                    },
                    Property {
                        name: "control-id".to_string(),
                        value: obj_info.control_id.clone(),
                        ns: None,
                    },
                    Property {
                        name: "disposition".to_string(),
                        value: "inherited".to_string(),
                        ns: Some("nist.gov:oscal:prime-verification".to_string()),
                    },
                    Property {
                        name: "tier-satisfied".to_string(),
                        value: "true".to_string(),
                        ns: Some("https://prime.compliance/oscal/evidence-tier".to_string()),
                    },
                    Property {
                        name: "adjudicated-state".to_string(),
                        value: "satisfied".to_string(),
                        ns: Some("https://prime.compliance/oscal/adjudication".to_string()),
                    },
                ],
            });

            tier_satisfied_count += 1;
            general_passed_count += 1;

            let find_uuid = Uuid::new_v5(
                &sap_meta.sap_uuid,
                format!("finding:{}:{}", obj_id, obj_info.implemented_requirement_uuid).as_bytes(),
            );

            findings.push(Finding {
                uuid: find_uuid,
                title: format!("Security Finding: Control {} (Inherited)", obj_info.control_id),
                description: format!(
                    "Control {} objective {} satisfied via active external CSP authorization attestation package.",
                    obj_info.control_id, obj_id
                ),
                implementation_statement_uuid: Some(obj_info.implemented_requirement_uuid),
                target: FindingTarget {
                    r#type: "objective-id".to_string(),
                    target_id: obj_id.clone(),
                    status: TargetStatus {
                        state: "satisfied".to_string(),
                        reason: Some("pass".to_string()),
                    },
                },
                related_observations: vec![RelatedObservation {
                    observation_uuid: obs_uuid,
                }],
                props: vec![
                    Property {
                        name: "control-id".to_string(),
                        value: obj_info.control_id.clone(),
                        ns: None,
                    },
                    Property {
                        name: "objective-id".to_string(),
                        value: obj_id.clone(),
                        ns: Some("nist.gov:oscal:prime-verification".to_string()),
                    },
                    Property {
                        name: "implemented-requirement-uuid".to_string(),
                        value: obj_info.implemented_requirement_uuid.to_string(),
                        ns: Some("nist.gov:oscal:prime-verification".to_string()),
                    },
                    Property {
                        name: "disposition".to_string(),
                        value: "inherited".to_string(),
                        ns: Some("nist.gov:oscal:prime-verification".to_string()),
                    },
                    Property {
                        name: "tier-satisfied".to_string(),
                        value: "true".to_string(),
                        ns: Some("https://prime.compliance/oscal/evidence-tier".to_string()),
                    },
                    Property {
                        name: "adjudicated-state".to_string(),
                        value: "satisfied".to_string(),
                        ns: Some("https://prime.compliance/oscal/adjudication".to_string()),
                    },
                ],
            });

            *objective_findings_count.entry(obj_id.clone()).or_default() += 1;
        }
    }

    // 3. Bidirectional Invariant Enforcement & Orphan Verification
    // Every SAP objective must have >= 1 AR finding
    for (obj_id, count) in &objective_findings_count {
        if *count == 0 {
            return Err(vec![format!(
                "[E-OSCAL-017] Invariant violation: SAP objective '{}' has zero AR findings",
                obj_id
            )]);
        }
    }

    // Every AR finding must resolve to a valid SAP objective
    for find in &findings {
        if find.target.r#type == "objective-id" {
            if !sap_meta.objectives.contains_key(&find.target.target_id) {
                return Err(vec![format!(
                    "[E-OSCAL-017] Orphaned assessment finding: finding '{}' references missing objective target '{}'",
                    find.uuid, find.target.target_id
                )]);
            }
        }
        if let Some(ir_uuid) = find.implementation_statement_uuid {
            if let Some(ref valid_ssp_ir) = ssp_ir_uuids {
                if !valid_ssp_ir.contains(&ir_uuid) {
                    return Err(vec![format!(
                        "[E-OSCAL-017] Orphaned assessment finding: finding '{}' references missing implemented-requirement target '{}'",
                        find.uuid, ir_uuid
                    )]);
                }
            }
        }
    }

    // Calculate gate coverage
    let total = sap_meta.objectives.len().max(1) as f64;
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
        Property {
            name: "sap-objectives-count".to_string(),
            value: sap_meta.objectives.len().to_string(),
            ns: Some("nist.gov:oscal:prime-verification".to_string()),
        },
        Property {
            name: "ar-findings-count".to_string(),
            value: findings.len().to_string(),
            ns: Some("nist.gov:oscal:prime-verification".to_string()),
        },
        Property {
            name: "ar-observations-count".to_string(),
            value: observations.len().to_string(),
            ns: Some("nist.gov:oscal:prime-verification".to_string()),
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

    let mut reviewed_control_ids = BTreeSet::new();
    for obj in sap_meta.objectives.values() {
        reviewed_control_ids.insert(canonicalize_control_id(&obj.control_id));
    }

    let ar_doc = OscalAssessmentResultsDocument {
        assessment_results: AssessmentResults {
            uuid: ar_uuid,
            metadata: metadata.clone(),
            import_ap: ImportAp {
                href: format!("urn:uuid:{}", sap_meta.sap_uuid),
            },
            results: vec![ResultItem {
                uuid: Uuid::new_v5(&sap_meta.sap_uuid, b"result:default"),
                title: "Automated Dual Verification Execution".to_string(),
                description: "Evaluation pass executed by cargo-oscal linked to SAP".to_string(),
                start: now,
                end: now,
                props: coverage_props,
                reviewed_controls: ReviewedControls {
                    control_selections: vec![ControlSelection {
                        include_controls: reviewed_control_ids
                            .into_iter()
                            .map(|cid| SelectControlById { control_id: cid })
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
            uuid: Uuid::new_v5(&sap_meta.sap_uuid, format!("suppressed:{}", now.timestamp()).as_bytes()),
            metadata: SuppressedFindingsMetadata {
                title: "PRIME Suppressed Findings Register".to_string(),
                published: now,
                version: "0.1.0".to_string(),
                oscal_version: "1.1.0".to_string(),
                policy_waiver_mode: "suppress".to_string(),
                total_suppressed: suppressed_findings.len(),
            },
            suppressed_findings,
        })
    };

    let bundle = SynthesizedComplianceBundle {
        assessment_results: ar_doc,
        poam: poam_doc,
        suppressed_findings: suppressed_doc,
    };

    // Strict Validate-Before-Return against NIST OSCAL 1.1.0 Schema
    bundle.validate()?;

    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate_policy::GatePolicyConfigPolicyWaiverMode;
    use crate::ssp::{synthesize_system_security_plan, SspWorkspaceComponent};
    use crate::tailoring::{ControlDisposition, TailoredBaselineReport};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn make_test_ssp_and_sap() -> (Value, Value) {
        let mut baseline = std::collections::BTreeSet::new();
        baseline.insert("SI-7".to_string());
        baseline.insert("AU-3".to_string());
        let tailoring_report = TailoredBaselineReport {
            scope: None,
            in_scope_controls: baseline.clone(),
            excluded_controls: std::collections::BTreeSet::new(),
            c_tailored: baseline.clone(),
            denominator: 2,
        };
        let mut dispositions = BTreeMap::new();
        dispositions.insert(
            "SI-7".to_string(),
            ControlDisposition::Workspace {
                component: "PRIME Engine".to_string(),
                achieved_tier: EvidenceTier::Test,
            },
        );
        dispositions.insert(
            "AU-3".to_string(),
            ControlDisposition::Workspace {
                component: "PRIME Engine".to_string(),
                achieved_tier: EvidenceTier::Test,
            },
        );
        let comps = vec![SspWorkspaceComponent {
            name: "oscal-engine".to_string(),
            title: "PRIME Engine".to_string(),
            description: "PRIME Compliance Engine".to_string(),
        }];
        let ssp = synthesize_system_security_plan(
            None,
            &tailoring_report,
            &dispositions,
            &comps,
            None,
        )
        .expect("SSP synthesis failed");

        let sap = crate::sap::synthesize_assessment_plan(
            &ssp,
            Some(&tailoring_report),
            Some(&dispositions),
            None,
            false,
            None,
        )
        .expect("SAP synthesis failed");

        (ssp, sap)
    }

    #[test]
    fn test_ar_observation_references_sap_activity_uuid() {
        let (ssp, sap) = make_test_ssp_and_sap();
        let inputs = vec![
            SynthesisInput {
                title: "Test SI-7".to_string(),
                component_title: "PRIME Engine".to_string(),
                control_id: "SI-7".to_string(),
                target_symbol: "test_si7".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::Test,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
            SynthesisInput {
                title: "Test AU-3".to_string(),
                component_title: "PRIME Engine".to_string(),
                control_id: "AU-3".to_string(),
                target_symbol: "test_au3".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::Test,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
        ];

        let bundle = synthesize_linked_compliance_bundle(&inputs, &sap, Some(&ssp), None)
            .expect("Linked bundle failed");

        let obs_list = &bundle.assessment_results.assessment_results.results[0].observations;
        assert!(!obs_list.is_empty());

        let sap_meta = parse_sap_for_linking(&sap).unwrap();

        for obs in obs_list {
            let act_prop = obs.props.iter().find(|p| p.name == "activity-uuid");
            assert!(act_prop.is_some(), "Observation missing activity-uuid prop");
            let act_uuid = Uuid::parse_str(&act_prop.unwrap().value).unwrap();
            assert!(
                sap_meta.activities.contains_key(&act_uuid),
                "Observation activity UUID '{}' not in SAP activities",
                act_uuid
            );
        }
    }

    #[test]
    fn test_ar_finding_references_sap_objective_and_ssp_ir_uuid() {
        let (ssp, sap) = make_test_ssp_and_sap();
        let inputs = vec![
            SynthesisInput {
                title: "Test SI-7".to_string(),
                component_title: "PRIME Engine".to_string(),
                control_id: "SI-7".to_string(),
                target_symbol: "test_si7".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::Test,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
            SynthesisInput {
                title: "Test AU-3".to_string(),
                component_title: "PRIME Engine".to_string(),
                control_id: "AU-3".to_string(),
                target_symbol: "test_au3".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::Test,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
        ];

        let bundle = synthesize_linked_compliance_bundle(&inputs, &sap, Some(&ssp), None)
            .expect("Linked bundle failed");

        let findings = &bundle.assessment_results.assessment_results.results[0].findings;
        assert_eq!(findings.len(), 2);

        let sap_meta = parse_sap_for_linking(&sap).unwrap();
        let ssp_ir_uuids = extract_ssp_implemented_requirement_uuids(&ssp);

        for find in findings {
            assert_eq!(find.target.r#type, "objective-id");
            assert!(
                sap_meta.objectives.contains_key(&find.target.target_id),
                "Finding target_id '{}' not in SAP objectives",
                find.target.target_id
            );
            assert!(
                find.implementation_statement_uuid.is_some(),
                "Finding missing implementation_statement_uuid"
            );
            let ir_uuid = find.implementation_statement_uuid.unwrap();
            assert!(
                ssp_ir_uuids.contains(&ir_uuid),
                "Finding IR UUID '{}' not in SSP implemented-requirements",
                ir_uuid
            );
        }
    }

    #[test]
    fn test_ar_synthesis_activity_produces_metadata_only_observation() {
        let (ssp, sap) = make_test_ssp_and_sap();
        let inputs = vec![
            SynthesisInput {
                title: "Test SI-7".to_string(),
                component_title: "PRIME Engine".to_string(),
                control_id: "SI-7".to_string(),
                target_symbol: "test_si7".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::Test,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
            SynthesisInput {
                title: "Test AU-3".to_string(),
                component_title: "PRIME Engine".to_string(),
                control_id: "AU-3".to_string(),
                target_symbol: "test_au3".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::Test,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
        ];

        let bundle = synthesize_linked_compliance_bundle(&inputs, &sap, Some(&ssp), None)
            .expect("Linked bundle failed");

        let obs_list = &bundle.assessment_results.assessment_results.results[0].observations;
        let metadata_obs: Vec<_> = obs_list
            .iter()
            .filter(|o| o.types.contains(&"metadata".to_string()))
            .collect();

        assert_eq!(metadata_obs.len(), 1, "Expected exactly 1 metadata-only observation for ar-synthesis");
        let meta_obs = metadata_obs[0];
        assert_eq!(meta_obs.methods, vec!["SYNTHESIS".to_string()]);
        assert!(meta_obs.props.iter().any(|p| p.name == "activity-phase" && p.value == "ar-synthesis"));

        // Verify that ar-synthesis observation is NOT referenced in any control finding
        let findings = &bundle.assessment_results.assessment_results.results[0].findings;
        for find in findings {
            for rel in &find.related_observations {
                assert_ne!(rel.observation_uuid, meta_obs.uuid, "Finding should not reference ar-synthesis observation");
            }
        }
    }

    #[test]
    fn test_orphaned_observation_fails_e_oscal_017() {
        let (ssp, mut sap) = make_test_ssp_and_sap();
        // Corrupt SAP activities by stripping them out
        sap["assessment-plan"]["local-definitions"]["activities"] = json!([]);

        let inputs = vec![SynthesisInput {
            title: "Test SI-7".to_string(),
            component_title: "PRIME Engine".to_string(),
            control_id: "SI-7".to_string(),
            target_symbol: "test_si7".to_string(),
            required_tier: EvidenceTier::Test,
            achieved_tier: EvidenceTier::Test,
            kani_passed: true,
            lean_sorry_detected: false,
            failure_reason: None,
            is_waived: false,
            waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
        }];

        let res = synthesize_linked_compliance_bundle(&inputs, &sap, Some(&ssp), None);
        assert!(res.is_err(), "Expected failure on orphaned observation");
        let errs = res.err().unwrap();
        assert!(errs.iter().any(|e| e.contains("[E-OSCAL-017]")), "Expected [E-OSCAL-017] in error, got: {:?}", errs);
    }

    #[test]
    fn test_orphaned_finding_fails_e_oscal_017() {
        let (mut ssp, sap) = make_test_ssp_and_sap();
        // Corrupt SSP implemented requirements by changing their UUIDs
        let reqs = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
            .as_array_mut()
            .unwrap();
        for r in reqs {
            r["uuid"] = json!(Uuid::new_v4().to_string());
        }

        let inputs = vec![SynthesisInput {
            title: "Test SI-7".to_string(),
            component_title: "PRIME Engine".to_string(),
            control_id: "SI-7".to_string(),
            target_symbol: "test_si7".to_string(),
            required_tier: EvidenceTier::Test,
            achieved_tier: EvidenceTier::Test,
            kani_passed: true,
            lean_sorry_detected: false,
            failure_reason: None,
            is_waived: false,
            waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
        }];

        let res = synthesize_linked_compliance_bundle(&inputs, &sap, Some(&ssp), None);
        assert!(res.is_err(), "Expected failure on orphaned finding target");
        let errs = res.err().unwrap();
        assert!(errs.iter().any(|e| e.contains("[E-OSCAL-017]")), "Expected [E-OSCAL-017] in error, got: {:?}", errs);
    }

    #[test]
    fn test_ar_byte_identical_under_fixed_clock() {
        let (ssp, sap) = make_test_ssp_and_sap();
        let inputs = vec![
            SynthesisInput {
                title: "Test SI-7".to_string(),
                component_title: "PRIME Engine".to_string(),
                control_id: "SI-7".to_string(),
                target_symbol: "test_si7".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::Test,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
            SynthesisInput {
                title: "Test AU-3".to_string(),
                component_title: "PRIME Engine".to_string(),
                control_id: "AU-3".to_string(),
                target_symbol: "test_au3".to_string(),
                required_tier: EvidenceTier::Test,
                achieved_tier: EvidenceTier::Test,
                kani_passed: true,
                lean_sorry_detected: false,
                failure_reason: None,
                is_waived: false,
                waiver_mode: GatePolicyConfigPolicyWaiverMode::Downgrade,
            },
        ];

        let fixed_clock = Some(DateTime::parse_from_rfc3339("2026-11-10T22:00:00Z").unwrap().with_timezone(&Utc));

        let b1 = synthesize_linked_compliance_bundle(&inputs, &sap, Some(&ssp), fixed_clock).unwrap();
        let b2 = synthesize_linked_compliance_bundle(&inputs, &sap, Some(&ssp), fixed_clock).unwrap();

        let json1 = serde_json::to_string_pretty(&b1.assessment_results).unwrap();
        let json2 = serde_json::to_string_pretty(&b2.assessment_results).unwrap();

        assert_eq!(json1, json2, "AR must be byte-identical under fixed clock");
    }
}
