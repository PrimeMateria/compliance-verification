//! System Security Plan (SSP) Synthesis Engine per Step 5a
//! Synthesizes schema-valid NIST OSCAL 1.1.0 System Security Plans under validate-before-write discipline

use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

use crate::gate_policy::GatePolicyConfig;
use crate::tailoring::{get_effective_clock, ControlDisposition, TailoredBaselineReport};
use crate::{validate_system_security_plan, PRIME_OSCAL_NAMESPACE};

#[derive(Debug, Clone)]
pub struct SspWorkspaceComponent {
    pub name: String,
    pub title: String,
    pub description: String,
}

/// Synthesize a schema-valid NIST OSCAL 1.1.0 System Security Plan JSON document
pub fn synthesize_system_security_plan(
    policy_config: Option<&GatePolicyConfig>,
    tailoring_report: &TailoredBaselineReport,
    control_dispositions: &BTreeMap<String, ControlDisposition>,
    workspace_components: &[SspWorkspaceComponent],
    injected_now: Option<DateTime<Utc>>,
) -> Result<serde_json::Value, Vec<String>> {
    let mut errors = Vec::new();

    // 1. Check for Unsatisfied controls: fail closed immediately
    let mut unsatisfied_controls = Vec::new();
    for (cid, disposition) in control_dispositions {
        if matches!(disposition, ControlDisposition::Unsatisfied) {
            unsatisfied_controls.push(cid.clone());
        }
    }

    if !unsatisfied_controls.is_empty() {
        return Err(vec![format!(
            "[E-OSCAL-013] Cannot synthesize System Security Plan: {} control(s) in tailored baseline are unsatisfied: {}",
            unsatisfied_controls.len(),
            unsatisfied_controls.join(", ")
        )]);
    }

    let now = get_effective_clock(injected_now);
    let now_str = now.to_rfc3339();

    // Deterministic UUIDs
    let ssp_uuid = Uuid::new_v5(
        &PRIME_OSCAL_NAMESPACE,
        b"ssp:document:prime-continuous-verification",
    );
    let managing_party_uuid = Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"ssp:party:prime-core-team");
    let user_uuid = Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"ssp:user:automated-verifier");

    // Parties
    let mut parties = vec![json!({
        "uuid": managing_party_uuid.to_string(),
        "type": "organization",
        "name": "PRIME Continuous Verification Core Team"
    })];

    // Profile href
    let profile_name = policy_config
        .and_then(|p| p.catalog.as_ref())
        .and_then(|c| c.profile.as_deref())
        .unwrap_or("FedRAMP_High");
    let import_profile_href = format!("urn:oscal:profile:{}", profile_name.to_lowercase());

    // Leveraged Authorizations & External Components
    let mut leveraged_authorizations = Vec::new();
    let mut leveraged_component_map: HashMap<String, (Uuid, Uuid)> = HashMap::new(); // source_id -> (comp_uuid, lev_auth_uuid)
    let mut components = Vec::new();

    if let Some(cat) = policy_config.and_then(|p| p.catalog.as_ref()) {
        for (src_id, inh) in &cat.inheritance {
            let lev_auth_uuid = match Uuid::parse_str(&inh.leveraged_authorization_uuid) {
                Ok(u) if u.get_version_num() == 4 || u.get_version_num() == 5 => u,
                _ => Uuid::new_v5(
                    &PRIME_OSCAL_NAMESPACE,
                    format!("ssp:leveraged-auth:{}", src_id).as_bytes(),
                ),
            };
            let party_uuid = Uuid::new_v5(
                &PRIME_OSCAL_NAMESPACE,
                format!("ssp:party:leveraged:{}", src_id).as_bytes(),
            );
            let comp_uuid = Uuid::new_v5(
                &PRIME_OSCAL_NAMESPACE,
                format!("ssp:component:leveraged:{}", src_id).as_bytes(),
            );

            leveraged_component_map.insert(src_id.clone(), (comp_uuid, lev_auth_uuid));

            parties.push(json!({
                "uuid": party_uuid.to_string(),
                "type": "organization",
                "name": inh.title.clone()
            }));

            leveraged_authorizations.push(json!({
                "uuid": lev_auth_uuid.to_string(),
                "title": inh.title.clone(),
                "party-uuid": party_uuid.to_string(),
                "date-authorized": "2024-01-01"
            }));

            components.push(json!({
                "uuid": comp_uuid.to_string(),
                "type": "interconnection",
                "title": format!("Leveraged Boundary: {}", inh.title),
                "description": inh.boundary_description.clone().unwrap_or_else(|| format!("Leveraged authorization boundary for {}", inh.title)),
                "props": [
                    { "name": "implementation-point", "value": "external" },
                    { "name": "leveraged-authorization-uuid", "value": lev_auth_uuid.to_string() }
                ],
                "status": {
                    "state": "operational"
                }
            }));
        }
    }

    // Workspace Components
    let mut workspace_component_map: HashMap<String, Uuid> = HashMap::new();
    if workspace_components.is_empty() {
        // Default components from PRIME
        let default_pkgs = [
            (
                "oscal-engine",
                "PRIME OSCAL Compliance Engine",
                "OSCAL compiler, synthesis, and gate evaluation engine",
            ),
            (
                "cargo-oscal",
                "PRIME OSCAL CLI Orchestrator",
                "Continuous verification driver and verification orchestrator",
            ),
            (
                "sha256-demo",
                "PRIME SHA-256 Formal Verification Demo",
                "Cryptographic kernel with Kani CBMC and Lean 4 formal proofs",
            ),
        ];
        for (pkg_name, title, desc) in default_pkgs {
            let comp_uuid = Uuid::new_v5(
                &PRIME_OSCAL_NAMESPACE,
                format!("ssp:component:workspace:{}", pkg_name).as_bytes(),
            );
            workspace_component_map.insert(pkg_name.to_string(), comp_uuid);
            components.push(json!({
                "uuid": comp_uuid.to_string(),
                "type": "software",
                "title": title,
                "description": desc,
                "status": {
                    "state": "operational"
                }
            }));
        }
    } else {
        for c in workspace_components {
            let comp_uuid = Uuid::new_v5(
                &PRIME_OSCAL_NAMESPACE,
                format!("ssp:component:workspace:{}", c.name).as_bytes(),
            );
            workspace_component_map.insert(c.name.clone(), comp_uuid);
            components.push(json!({
                "uuid": comp_uuid.to_string(),
                "type": "software",
                "title": c.title.clone(),
                "description": c.description.clone(),
                "status": {
                    "state": "operational"
                }
            }));
        }
    }

    // Implemented Requirements
    let mut implemented_requirements = Vec::new();
    let default_comp_uuid = components[0]["uuid"].as_str().unwrap().to_string();

    for control_id in &tailoring_report.c_tailored {
        let canonical_id = crate::canonicalize_control_id(control_id);
        let req_uuid = Uuid::new_v5(
            &PRIME_OSCAL_NAMESPACE,
            format!("ssp:imp-req:{}", canonical_id).as_bytes(),
        );

        let disposition = control_dispositions
            .get(&canonical_id)
            .or_else(|| control_dispositions.get(control_id));
        match disposition {
            Some(ControlDisposition::Workspace {
                component,
                achieved_tier,
            }) => {
                let comp_uuid = workspace_component_map
                    .get(component)
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| default_comp_uuid.clone());
                let by_comp_uuid = Uuid::new_v5(
                    &PRIME_OSCAL_NAMESPACE,
                    format!("ssp:by-comp:{}:{}", canonical_id, component).as_bytes(),
                );

                implemented_requirements.push(json!({
                    "uuid": req_uuid.to_string(),
                    "control-id": canonical_id.clone(),
                    "by-components": [
                        {
                            "component-uuid": comp_uuid,
                            "uuid": by_comp_uuid.to_string(),
                            "description": format!("Control '{}' implemented by component '{}' with verified evidence tier '{}'.", canonical_id, component, achieved_tier),
                            "implementation-status": {
                                "state": "implemented"
                            },
                            "props": [
                                { "name": "implementation-point", "value": "internal" },
                                { "name": "achieved-evidence-tier", "value": achieved_tier.to_string() }
                            ]
                        }
                    ]
                }));
            }
            Some(ControlDisposition::Inherited { source_id }) => {
                let (comp_uuid, lev_auth_uuid) = match leveraged_component_map.get(source_id) {
                    Some((cu, lu)) => (cu.to_string(), lu.to_string()),
                    None => {
                        let cu = Uuid::new_v5(
                            &PRIME_OSCAL_NAMESPACE,
                            format!("ssp:component:leveraged:{}", source_id).as_bytes(),
                        )
                        .to_string();
                        let lu = Uuid::new_v5(
                            &PRIME_OSCAL_NAMESPACE,
                            format!("ssp:leveraged-auth:{}", source_id).as_bytes(),
                        )
                        .to_string();
                        (cu, lu)
                    }
                };
                let by_comp_uuid = Uuid::new_v5(
                    &PRIME_OSCAL_NAMESPACE,
                    format!("ssp:by-comp:{}:{}", canonical_id, source_id).as_bytes(),
                );
                let inherited_item_uuid = Uuid::new_v5(
                    &PRIME_OSCAL_NAMESPACE,
                    format!("ssp:inherited-item:{}:{}", canonical_id, source_id).as_bytes(),
                );

                implemented_requirements.push(json!({
                    "uuid": req_uuid.to_string(),
                    "control-id": canonical_id.clone(),
                    "by-components": [
                        {
                            "component-uuid": comp_uuid,
                            "uuid": by_comp_uuid.to_string(),
                            "description": format!("Control '{}' inherited from external authorization boundary '{}'.", canonical_id, source_id),
                            "implementation-status": {
                                "state": "implemented"
                            },
                            "props": [
                                { "name": "implementation-point", "value": "external" },
                                { "name": "inheritance-source", "value": source_id.clone() }
                            ],
                            "inherited": [
                                {
                                    "uuid": inherited_item_uuid.to_string(),
                                    "provided-uuid": lev_auth_uuid,
                                    "description": format!("Capability inherited from leveraged authorization source '{}'", source_id)
                                }
                            ]
                        }
                    ]
                }));
            }
            Some(ControlDisposition::Unsatisfied) | None => {
                errors.push(format!("[E-OSCAL-013] Control '{}' in tailored baseline has no satisfaction disposition", canonical_id));
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let control_impl_obj = json!({
        "description": "Tailored baseline control implementations verified via PRIME continuous verification.",
        "implemented-requirements": implemented_requirements
    });

    let mut system_impl_obj = json!({
        "users": [
            {
                "uuid": user_uuid.to_string(),
                "title": "PRIME Continuous Verification Compiler Pipeline"
            }
        ],
        "components": components
    });
    if !leveraged_authorizations.is_empty() {
        system_impl_obj["leveraged-authorizations"] = json!(leveraged_authorizations);
    }

    let ssp_doc = json!({
        "system-security-plan": {
            "uuid": ssp_uuid.to_string(),
            "metadata": {
                "title": "PRIME Continuous Verification System Security Plan",
                "published": now_str,
                "last-modified": now_str,
                "version": "0.1.0",
                "oscal-version": "1.1.0",
                "parties": parties
            },
            "import-profile": {
                "href": import_profile_href
            },
            "system-characteristics": {
                "system-ids": [
                    {
                        "id": "PRIME-SYSTEM-001"
                    }
                ],
                "system-name": "PRIME Continuous Verification Platform",
                "description": "Continuous authorization and formal compiler verification platform for Lean 4 and Rust systems.",
                "security-sensitivity-level": "high",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"ssp:info-type:assurance-telemetry").to_string(),
                            "title": "Software Verification & Assurance Telemetry",
                            "description": "Kani CBMC proofs, Lean 4 kernel theorems, and automated compliance telemetry.",
                            "confidentiality-impact": { "base": "fips-199-moderate" },
                            "integrity-impact": { "base": "fips-199-high" },
                            "availability-impact": { "base": "fips-199-moderate" }
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": "fips-199-moderate",
                    "security-objective-integrity": "fips-199-high",
                    "security-objective-availability": "fips-199-moderate"
                },
                "status": {
                    "state": "operational"
                },
                "authorization-boundary": {
                    "description": "Continuous verification boundaries enclosing Lean/Rust workspace crates, CBMC solver, and Lean 4 kernel."
                }
            },
            "system-implementation": system_impl_obj,
            "control-implementation": control_impl_obj
        }
    });

    // Validate-before-write against official NIST OSCAL SSP schema
    validate_system_security_plan(&ssp_doc)?;

    Ok(ssp_doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate_policy::{
        GatePolicyConfig, GatePolicyConfigCatalog, GatePolicyConfigCatalogInheritanceValue,
    };
    use crate::EvidenceTier;
    use chrono::TimeZone;
    use std::collections::BTreeSet;

    fn make_test_setup() -> (
        GatePolicyConfig,
        TailoredBaselineReport,
        BTreeMap<String, ControlDisposition>,
        Vec<SspWorkspaceComponent>,
        DateTime<Utc>,
    ) {
        let fixed_now = Utc.with_ymd_and_hms(2026, 11, 10, 12, 0, 0).unwrap();

        let mut inheritance = HashMap::new();
        inheritance.insert(
            "aws-east-1".to_string(),
            GatePolicyConfigCatalogInheritanceValue {
                attestation_expiry: "2027-01-01T00:00:00Z".to_string(),
                boundary_description: Some(
                    "AWS US East 1 FedRAMP High Authorization Boundary".to_string(),
                ),
                controls: vec!["pe-3".to_string()],
                leveraged_authorization_uuid: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".to_string(),
                title: "AWS GovCloud Infrastructure".to_string(),
            },
        );

        let mut config: GatePolicyConfig = toml::from_str(
            r#"
            [policy]
            require_kani_pass = false
            forbid_lean_sorry = false
            min_control_coverage = 1.0
            min_default_tier = "test"
            coverage_basis = "baseline_catalog"
            waiver_mode = "downgrade"

            [promotion]
            mode = "auto"
            staging_dir = "artifacts/oscal/staging"
            release_dir = "artifacts/oscal"
        "#,
        )
        .unwrap();

        config.catalog = Some(GatePolicyConfigCatalog {
            baseline: Some("NIST_SP_800_53_Rev5".to_string()),
            profile: Some("FedRAMP_High".to_string()),
            inheritance,
            tailoring: None,
        });

        let mut c_tailored = BTreeSet::new();
        c_tailored.insert("ac-1".to_string());
        c_tailored.insert("pe-3".to_string());
        c_tailored.insert("si-7(1)".to_string());

        let tailoring_report = TailoredBaselineReport {
            scope: Some("FedRAMP_High".to_string()),
            in_scope_controls: c_tailored.clone(),
            excluded_controls: BTreeSet::new(),
            denominator: 3,
            c_tailored,
        };

        let mut dispositions = BTreeMap::new();
        dispositions.insert(
            "ac-1".to_string(),
            ControlDisposition::Workspace {
                component: "oscal-engine".to_string(),
                achieved_tier: EvidenceTier::Test,
            },
        );
        dispositions.insert(
            "si-7(1)".to_string(),
            ControlDisposition::Workspace {
                component: "sha256-demo".to_string(),
                achieved_tier: EvidenceTier::FormalKernel,
            },
        );
        dispositions.insert(
            "pe-3".to_string(),
            ControlDisposition::Inherited {
                source_id: "aws-east-1".to_string(),
            },
        );

        let workspace_components = vec![
            SspWorkspaceComponent {
                name: "oscal-engine".to_string(),
                title: "PRIME OSCAL Compliance Engine".to_string(),
                description: "OSCAL synthesis engine".to_string(),
            },
            SspWorkspaceComponent {
                name: "sha256-demo".to_string(),
                title: "PRIME SHA-256 Demo".to_string(),
                description: "Formal verification kernel".to_string(),
            },
        ];

        (
            config,
            tailoring_report,
            dispositions,
            workspace_components,
            fixed_now,
        )
    }

    #[test]
    fn test_synthesize_system_security_plan_schema_valid() {
        let (config, report, dispositions, components, now) = make_test_setup();
        let res = synthesize_system_security_plan(
            Some(&config),
            &report,
            &dispositions,
            &components,
            Some(now),
        );
        assert!(res.is_ok(), "SSP synthesis must succeed: {:?}", res.err());
        let ssp_doc = res.unwrap();

        // Validate directly against official schema
        assert!(validate_system_security_plan(&ssp_doc).is_ok());

        let ssp = &ssp_doc["system-security-plan"];
        assert_eq!(ssp["metadata"]["oscal-version"], "1.1.0");
        assert_eq!(ssp["metadata"]["published"], now.to_rfc3339());
        assert_eq!(
            ssp["import-profile"]["href"],
            "urn:oscal:profile:fedramp_high"
        );

        let imp_reqs = ssp["control-implementation"]["implemented-requirements"]
            .as_array()
            .unwrap();
        assert_eq!(imp_reqs.len(), 3);
    }

    #[test]
    fn test_synthesize_system_security_plan_unsatisfied_fails_closed() {
        let (config, report, mut dispositions, components, now) = make_test_setup();
        dispositions.insert("ac-1".to_string(), ControlDisposition::Unsatisfied);

        let res = synthesize_system_security_plan(
            Some(&config),
            &report,
            &dispositions,
            &components,
            Some(now),
        );
        assert!(
            res.is_err(),
            "SSP synthesis must fail closed when control is unsatisfied"
        );
        let errs = res.err().unwrap();
        assert!(errs
            .iter()
            .any(|e| e.contains("[E-OSCAL-013]") && e.contains("ac-1")));
    }

    #[test]
    fn test_synthesize_system_security_plan_deterministic_uuid_and_clock() {
        let (config, report, dispositions, components, now) = make_test_setup();
        let res1 = synthesize_system_security_plan(
            Some(&config),
            &report,
            &dispositions,
            &components,
            Some(now),
        )
        .unwrap();

        let res2 = synthesize_system_security_plan(
            Some(&config),
            &report,
            &dispositions,
            &components,
            Some(now),
        )
        .unwrap();

        let json1 = serde_json::to_string(&res1).unwrap();
        let json2 = serde_json::to_string(&res2).unwrap();
        assert_eq!(
            json1, json2,
            "SSP synthesis must be strictly deterministic and byte-identical"
        );
    }

    #[test]
    fn test_workspace_vs_inherited_component_mapping() {
        let (config, report, dispositions, components, now) = make_test_setup();
        let ssp_doc = synthesize_system_security_plan(
            Some(&config),
            &report,
            &dispositions,
            &components,
            Some(now),
        )
        .unwrap();

        let ssp = &ssp_doc["system-security-plan"];

        // 1. Verify components in system-implementation
        let system_components = ssp["system-implementation"]["components"]
            .as_array()
            .unwrap();
        let leveraged_comp = system_components
            .iter()
            .find(|c| c["type"] == "interconnection")
            .unwrap();
        assert_eq!(
            leveraged_comp["title"],
            "Leveraged Boundary: AWS GovCloud Infrastructure"
        );

        let software_comps: Vec<_> = system_components
            .iter()
            .filter(|c| c["type"] == "software")
            .collect();
        assert_eq!(software_comps.len(), 2);

        // 2. Verify leveraged authorization
        let lev_auths = ssp["system-implementation"]["leveraged-authorizations"]
            .as_array()
            .unwrap();
        assert_eq!(lev_auths.len(), 1);
        let lev_auth_uuid = lev_auths[0]["uuid"].as_str().unwrap();
        assert_eq!(lev_auth_uuid, "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");

        // 3. Verify implemented requirements mapping
        let imp_reqs = ssp["control-implementation"]["implemented-requirements"]
            .as_array()
            .unwrap();

        // Check workspace requirement: si-7(1) -> canonicalized to si-7.1
        let si7 = imp_reqs
            .iter()
            .find(|r| r["control-id"] == "si-7.1")
            .unwrap();
        let si7_by_comp = &si7["by-components"][0];
        assert_eq!(si7_by_comp["implementation-status"]["state"], "implemented");
        let si7_props = si7_by_comp["props"].as_array().unwrap();
        assert!(si7_props
            .iter()
            .any(|p| p["name"] == "implementation-point" && p["value"] == "internal"));
        assert!(si7_props
            .iter()
            .any(|p| p["name"] == "achieved-evidence-tier" && p["value"] == "formal_kernel"));

        // Check inherited requirement: pe-3
        let pe3 = imp_reqs.iter().find(|r| r["control-id"] == "pe-3").unwrap();
        let pe3_by_comp = &pe3["by-components"][0];
        assert_eq!(pe3_by_comp["implementation-status"]["state"], "implemented");
        let pe3_props = pe3_by_comp["props"].as_array().unwrap();
        assert!(pe3_props
            .iter()
            .any(|p| p["name"] == "implementation-point" && p["value"] == "external"));
        assert!(pe3_props
            .iter()
            .any(|p| p["name"] == "inheritance-source" && p["value"] == "aws-east-1"));

        // Inherited item must match leveraged authorization UUID
        let inherited_items = pe3_by_comp["inherited"].as_array().unwrap();
        assert_eq!(inherited_items[0]["provided-uuid"], lev_auth_uuid);
    }

    #[test]
    fn test_step_5b_boundary_guard_automated_artifacts_contain_no_human_narratives() {
        let (config, report, dispositions, components, now) = make_test_setup();
        let ssp_doc = synthesize_system_security_plan(
            Some(&config),
            &report,
            &dispositions,
            &components,
            Some(now),
        )
        .unwrap();

        let ssp_str = serde_json::to_string(&ssp_doc).unwrap().to_lowercase();

        // Step 5b human audit narrative markers that must NEVER be injected into machine SSP
        let forbidden_step_5b_markers = [
            "personnel vetting",
            "background check",
            "physical facility diagram",
            "visitor log",
            "escort policy",
            "auditor sign-off",
            "manual operational procedure",
            "qualitative narrative",
        ];

        for marker in forbidden_step_5b_markers {
            assert!(
                !ssp_str.contains(marker),
                "Machine SSP must not contain Step 5b human narrative field: '{}'",
                marker
            );
        }

        // Structural guarantee: Must verify schema validity
        assert!(validate_system_security_plan(&ssp_doc).is_ok());
    }
}
