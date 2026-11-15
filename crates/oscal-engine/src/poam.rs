//! Plan of Action and Milestones (POA&M) Lifecycle State Machine
//!
//! Implements deterministic continuous tracking of compliance defects, waivers,
//! and milestones across build and assessment iterations per NIST SP 800-53 CA-5.

use chrono::{DateTime, Utc};
use oscal_diagnostics::OscalErrorCode;
use oscal_types::{
    Metadata, OscalPoamDocument, PlanOfActionAndMilestones, PoamItem, Property, RelatedFinding,
    RelatedObservation,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use uuid::Uuid;

use crate::{validate_poam, PRIME_OSCAL_NAMESPACE};

/// Formal lifecycle states for a POA&M item
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoamState {
    Open,
    InProgress,
    Closed,
    RiskAccepted,
    FalsePositive,
}

impl PoamState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in_progress",
            Self::Closed => "closed",
            Self::RiskAccepted => "risk_accepted",
            Self::FalsePositive => "false_positive",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Open | Self::InProgress)
    }
}

impl std::fmt::Display for PoamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for PoamState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_lowercase().replace('-', "_");
        match normalized.as_str() {
            "open" => Ok(Self::Open),
            "in_progress" | "inprogress" => Ok(Self::InProgress),
            "closed" | "resolved" => Ok(Self::Closed),
            "risk_accepted" | "riskaccepted" => Ok(Self::RiskAccepted),
            "false_positive" | "falsepositive" => Ok(Self::FalsePositive),
            _ => Err(format!("Unknown POA&M state: '{}'", s)),
        }
    }
}

/// A recorded state transition event in a POA&M item's lifecycle history
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoamTransitionEvent {
    pub timestamp: DateTime<Utc>,
    pub from_state: PoamState,
    pub to_state: PoamState,
    pub actor: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_citation: Option<String>,
}

/// Validates whether a state transition is legal under the formal state machine
pub fn can_transition(from: PoamState, to: PoamState) -> bool {
    if from == to {
        return true;
    }
    match from {
        PoamState::Open => matches!(
            to,
            PoamState::InProgress
                | PoamState::Closed
                | PoamState::RiskAccepted
                | PoamState::FalsePositive
        ),
        PoamState::InProgress => matches!(
            to,
            PoamState::Open
                | PoamState::Closed
                | PoamState::RiskAccepted
                | PoamState::FalsePositive
        ),
        PoamState::RiskAccepted => matches!(to, PoamState::Open | PoamState::Closed),
        PoamState::FalsePositive => matches!(to, PoamState::Open),
        PoamState::Closed => matches!(to, PoamState::Open),
    }
}

/// Validates state transition and citation requirements, returning [E-OSCAL-018] on violation
pub fn validate_poam_transition(
    from: PoamState,
    to: PoamState,
    evidence_citation: Option<&str>,
) -> Result<(), String> {
    if !can_transition(from, to) {
        return Err(format!(
            "POA&M state transition from '{}' to '{}' is invalid under state machine rules [{}]",
            from,
            to,
            OscalErrorCode::POAMStateTransitionInvalid.as_str()
        ));
    }

    if to == PoamState::RiskAccepted {
        let citation_valid = evidence_citation
            .map(|c| !c.trim().is_empty())
            .unwrap_or(false);
        if !citation_valid {
            return Err(format!(
                "POA&M state transition to 'risk_accepted' requires a non-empty evidence citation or waiver rationale [{}]",
                OscalErrorCode::POAMStateTransitionInvalid.as_str()
            ));
        }
    }

    if to == PoamState::FalsePositive {
        let citation_valid = evidence_citation
            .map(|c| !c.trim().is_empty())
            .unwrap_or(false);
        if !citation_valid {
            return Err(format!(
                "POA&M state transition to 'false_positive' requires a non-empty justification and evidence reference [{}]",
                OscalErrorCode::POAMStateTransitionInvalid.as_str()
            ));
        }
    }

    Ok(())
}

/// Computes a deterministic UUIDv5 identifier for a POA&M item
pub fn compute_poam_item_uuid(
    canonical_control_id: &str,
    source_kind: &str,
    source_id: &str,
    finding_category: &str,
) -> Uuid {
    let seed = format!(
        "poam-item:{}:{}:{}:{}",
        canonical_control_id.trim().to_lowercase(),
        source_kind.trim().to_lowercase(),
        source_id.trim(),
        finding_category.trim().to_lowercase()
    );
    Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, seed.as_bytes())
}

/// Defect input observed during compiler verification
#[derive(Debug, Clone, PartialEq)]
pub struct PoamDefectInput {
    pub canonical_control_id: String,
    pub source_kind: String,
    pub source_id: String,
    pub finding_category: String,
    pub title: String,
    pub description: String,
    pub finding_uuid: Option<Uuid>,
    pub observation_uuid: Option<Uuid>,
    pub activity_uuid: Option<Uuid>,
    pub implementation_statement_uuid: Option<Uuid>,
    pub remediation_deadline: Option<DateTime<Utc>>,
    pub initial_state: Option<PoamState>,
    pub evidence_citation: Option<String>,
}

/// Configuration caps and deadline rules for continuous POA&M tracking
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PoamCapsConfig {
    pub max_open_items: Option<usize>,
    pub fail_on_overdue: bool,
}

/// Telemetry outcome of POA&M state synchronization
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PoamSyncOutcome {
    pub new_items: Vec<Uuid>,
    pub reopened_items: Vec<Uuid>,
    pub resolved_items: Vec<Uuid>,
    pub active_open_count: usize,
    pub overdue_items: Vec<Uuid>,
    pub violations: Vec<String>,
}

/// Internal tracked representation of a POA&M item across lifecycle runs
#[derive(Debug, Clone, PartialEq)]
struct TrackedPoamItem {
    pub item: PoamItem,
    pub state: PoamState,
    pub history: Vec<PoamTransitionEvent>,
    pub remediation_deadline: Option<DateTime<Utc>>,
}

impl TrackedPoamItem {
    fn from_poam_item(item: PoamItem) -> Self {
        let mut state = PoamState::Open;
        let mut deadline = None;
        let mut history = Vec::new();

        for prop in &item.props {
            if prop.name == "status" || prop.name == "poam-state" {
                if let Ok(st) = PoamState::from_str(&prop.value) {
                    state = st;
                }
            } else if prop.name == "remediation-deadline" || prop.name == "target-date" {
                if let Ok(dt) = DateTime::parse_from_rfc3339(&prop.value) {
                    deadline = Some(dt.with_timezone(&Utc));
                }
            } else if prop.name == "transition-event" {
                if let Ok(evt) = serde_json::from_str::<PoamTransitionEvent>(&prop.value) {
                    history.push(evt);
                }
            }
        }

        Self {
            item,
            state,
            history,
            remediation_deadline: deadline,
        }
    }

    fn to_poam_item(&self) -> PoamItem {
        let mut item = self.item.clone();
        item.props.retain(|p| {
            p.name != "status"
                && p.name != "poam-state"
                && p.name != "transition-event"
                && p.name != "remediation-deadline"
        });

        // Set authoritative state properties
        item.props.push(Property {
            name: "status".to_string(),
            value: self.state.as_str().to_string(),
            ns: Some("https://prime.compliance/oscal/poam".to_string()),
        });
        item.props.push(Property {
            name: "poam-state".to_string(),
            value: self.state.as_str().to_string(),
            ns: Some("https://prime.compliance/oscal/poam".to_string()),
        });

        if let Some(dl) = self.remediation_deadline {
            item.props.push(Property {
                name: "remediation-deadline".to_string(),
                value: dl.to_rfc3339(),
                ns: None,
            });
        }

        // Record transition events in props for lossless persistence
        for event in &self.history {
            if let Ok(serialized) = serde_json::to_string(event) {
                item.props.push(Property {
                    name: "transition-event".to_string(),
                    value: serialized,
                    ns: Some("https://prime.compliance/oscal/poam/history".to_string()),
                });
            }
        }

        item
    }
}

/// Synchronizes compiler verification defects with existing POA&M state,
/// enforcing transitions, deadlines, and caps under fail-closed discipline
pub fn sync_poam_state(
    existing_doc: Option<&OscalPoamDocument>,
    defects: &[PoamDefectInput],
    now: DateTime<Utc>,
    caps: Option<&PoamCapsConfig>,
) -> Result<(OscalPoamDocument, PoamSyncOutcome), Vec<String>> {
    let mut tracked_map: BTreeMap<Uuid, TrackedPoamItem> = BTreeMap::new();
    let mut outcome = PoamSyncOutcome::default();

    // 1. Ingest existing POA&M items
    if let Some(doc) = existing_doc {
        for item in &doc.plan_of_action_and_milestones.poam_items {
            tracked_map.insert(item.uuid, TrackedPoamItem::from_poam_item(item.clone()));
        }
    }

    let active_defect_uuids: BTreeSet<Uuid> = defects
        .iter()
        .map(|d| {
            compute_poam_item_uuid(
                &d.canonical_control_id,
                &d.source_kind,
                &d.source_id,
                &d.finding_category,
            )
        })
        .collect();

    // 2. Process incoming defects
    for defect in defects {
        let item_uuid = compute_poam_item_uuid(
            &defect.canonical_control_id,
            &defect.source_kind,
            &defect.source_id,
            &defect.finding_category,
        );

        let target_initial_state = defect.initial_state.unwrap_or(PoamState::Open);

        if let Some(tracked) = tracked_map.get_mut(&item_uuid) {
            // Existing item persists
            if tracked.state == PoamState::Closed {
                // Re-open defect that regressed
                if let Err(e) = validate_poam_transition(
                    PoamState::Closed,
                    PoamState::Open,
                    defect.evidence_citation.as_deref(),
                ) {
                    outcome.violations.push(e);
                } else {
                    tracked.history.push(PoamTransitionEvent {
                        timestamp: now,
                        from_state: PoamState::Closed,
                        to_state: PoamState::Open,
                        actor: "compiler-gate".to_string(),
                        reason: "Defect regressed during verification pass".to_string(),
                        evidence_citation: defect.evidence_citation.clone(),
                    });
                    tracked.state = PoamState::Open;
                    outcome.reopened_items.push(item_uuid);
                }
            } else if tracked.state != target_initial_state
                && target_initial_state == PoamState::RiskAccepted
            {
                // Explicit transition to risk accepted
                if let Err(e) = validate_poam_transition(
                    tracked.state,
                    PoamState::RiskAccepted,
                    defect.evidence_citation.as_deref(),
                ) {
                    outcome.violations.push(e);
                } else {
                    tracked.history.push(PoamTransitionEvent {
                        timestamp: now,
                        from_state: tracked.state,
                        to_state: PoamState::RiskAccepted,
                        actor: "policy-evaluator".to_string(),
                        reason: "Waiver applied under policy cap".to_string(),
                        evidence_citation: defect.evidence_citation.clone(),
                    });
                    tracked.state = PoamState::RiskAccepted;
                }
            }

            // Update evidence references
            if let Some(find_uuid) = defect.finding_uuid {
                if !tracked
                    .item
                    .related_findings
                    .iter()
                    .any(|rf| rf.finding_uuid == find_uuid)
                {
                    tracked.item.related_findings.push(RelatedFinding {
                        finding_uuid: find_uuid,
                    });
                }
            }
            if let Some(obs_uuid) = defect.observation_uuid {
                if !tracked
                    .item
                    .related_observations
                    .iter()
                    .any(|ro| ro.observation_uuid == obs_uuid)
                {
                    tracked.item.related_observations.push(RelatedObservation {
                        observation_uuid: obs_uuid,
                    });
                }
            }
            if let Some(dl) = defect.remediation_deadline {
                tracked.remediation_deadline = Some(dl);
            }
        } else {
            // New defect discovered
            if let Err(e) = validate_poam_transition(
                PoamState::Open,
                target_initial_state,
                defect.evidence_citation.as_deref(),
            ) {
                outcome.violations.push(e);
                continue;
            }

            let mut related_findings = Vec::new();
            if let Some(f_uuid) = defect.finding_uuid {
                related_findings.push(RelatedFinding {
                    finding_uuid: f_uuid,
                });
            }
            let mut related_observations = Vec::new();
            if let Some(o_uuid) = defect.observation_uuid {
                related_observations.push(RelatedObservation {
                    observation_uuid: o_uuid,
                });
            }

            let deadline = defect
                .remediation_deadline
                .unwrap_or_else(|| now + chrono::Duration::days(30));

            let mut props = vec![
                Property {
                    name: "control-id".to_string(),
                    value: defect.canonical_control_id.clone(),
                    ns: None,
                },
                Property {
                    name: "source-kind".to_string(),
                    value: defect.source_kind.clone(),
                    ns: None,
                },
                Property {
                    name: "source-id".to_string(),
                    value: defect.source_id.clone(),
                    ns: None,
                },
                Property {
                    name: "finding-category".to_string(),
                    value: defect.finding_category.clone(),
                    ns: None,
                },
                Property {
                    name: "target-date".to_string(),
                    value: deadline.to_rfc3339(),
                    ns: None,
                },
            ];

            if let Some(act_uuid) = defect.activity_uuid {
                props.push(Property {
                    name: "activity-uuid".to_string(),
                    value: act_uuid.to_string(),
                    ns: Some("https://prime.compliance/oscal/sap".to_string()),
                });
            }
            if let Some(ir_uuid) = defect.implementation_statement_uuid {
                props.push(Property {
                    name: "implementation-statement-uuid".to_string(),
                    value: ir_uuid.to_string(),
                    ns: Some("https://prime.compliance/oscal/ssp".to_string()),
                });
            }

            let initial_event = PoamTransitionEvent {
                timestamp: now,
                from_state: PoamState::Open,
                to_state: target_initial_state,
                actor: "compiler-gate".to_string(),
                reason: "Initial defect observation recorded".to_string(),
                evidence_citation: defect.evidence_citation.clone(),
            };

            let item = PoamItem {
                uuid: item_uuid,
                title: defect.title.clone(),
                description: defect.description.clone(),
                props,
                related_findings,
                related_observations,
                remarks: defect.evidence_citation.clone(),
            };

            let tracked = TrackedPoamItem {
                item,
                state: target_initial_state,
                history: vec![initial_event],
                remediation_deadline: Some(deadline),
            };

            tracked_map.insert(item_uuid, tracked);
            outcome.new_items.push(item_uuid);
        }
    }

    // 3. Resolve active items that no longer appear as defects
    for (uuid, tracked) in tracked_map.iter_mut() {
        if !active_defect_uuids.contains(uuid) && tracked.state.is_active() {
            if let Err(e) = validate_poam_transition(tracked.state, PoamState::Closed, None) {
                outcome.violations.push(e);
            } else {
                tracked.history.push(PoamTransitionEvent {
                    timestamp: now,
                    from_state: tracked.state,
                    to_state: PoamState::Closed,
                    actor: "compiler-gate".to_string(),
                    reason: "Defect resolved in verification passes".to_string(),
                    evidence_citation: None,
                });
                tracked.state = PoamState::Closed;
                outcome.resolved_items.push(*uuid);
            }
        }
    }

    // 4. Accounting & Cap / Deadline evaluations
    let mut final_poam_items = Vec::new();
    for (_, tracked) in tracked_map {
        if tracked.state.is_active() {
            outcome.active_open_count += 1;
            if let Some(dl) = tracked.remediation_deadline {
                if dl < now {
                    outcome.overdue_items.push(tracked.item.uuid);
                }
            }
        }
        final_poam_items.push(tracked.to_poam_item());
    }

    // Sort items deterministically by UUID string
    final_poam_items.sort_by_key(|a| a.uuid);

    if let Some(cfg) = caps {
        if let Some(max_open) = cfg.max_open_items {
            if outcome.active_open_count > max_open {
                outcome.violations.push(format!(
                    "Active open POA&M items count ({}) exceeds policy cap ({})",
                    outcome.active_open_count, max_open
                ));
            }
        }
        if cfg.fail_on_overdue && !outcome.overdue_items.is_empty() {
            outcome.violations.push(format!(
                "Active POA&M item(s) exceeded remediation deadline: {:?}",
                outcome.overdue_items
            ));
        }
    }

    let poam_doc = OscalPoamDocument {
        plan_of_action_and_milestones: PlanOfActionAndMilestones {
            uuid: Uuid::new_v5(&PRIME_OSCAL_NAMESPACE, b"poam:authoritative:prime"),
            metadata: Metadata {
                title: "PRIME Continuous Verification Plan of Action and Milestones".to_string(),
                published: now,
                last_modified: now,
                version: "0.1.0".to_string(),
                oscal_version: "1.1.0".to_string(),
                props: vec![
                    Property {
                        name: "active-open-count".to_string(),
                        value: outcome.active_open_count.to_string(),
                        ns: Some("https://prime.compliance/oscal/poam".to_string()),
                    },
                    Property {
                        name: "total-items".to_string(),
                        value: final_poam_items.len().to_string(),
                        ns: Some("https://prime.compliance/oscal/poam".to_string()),
                    },
                ],
            },
            poam_items: final_poam_items,
        },
    };

    // 5. In-memory schema validation before return
    let poam_val = serde_json::to_value(&poam_doc)
        .map_err(|e| vec![format!("Failed to serialize POA&M document: {}", e)])?;

    validate_poam(&poam_val)?;

    Ok((poam_doc, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poam_state_transitions_valid_and_invalid() {
        // Valid forward transitions
        assert!(can_transition(PoamState::Open, PoamState::InProgress));
        assert!(can_transition(PoamState::Open, PoamState::Closed));
        assert!(can_transition(PoamState::Open, PoamState::RiskAccepted));
        assert!(can_transition(PoamState::Open, PoamState::FalsePositive));

        assert!(can_transition(PoamState::InProgress, PoamState::Closed));
        assert!(can_transition(PoamState::InProgress, PoamState::Open));

        // Valid reopen
        assert!(can_transition(PoamState::Closed, PoamState::Open));

        // Invalid transitions
        assert!(!can_transition(PoamState::Closed, PoamState::InProgress));
        assert!(!can_transition(PoamState::Closed, PoamState::RiskAccepted));
        assert!(!can_transition(PoamState::FalsePositive, PoamState::Closed));
        assert!(!can_transition(
            PoamState::FalsePositive,
            PoamState::InProgress
        ));

        // Diagnostic validation
        let err =
            validate_poam_transition(PoamState::Closed, PoamState::RiskAccepted, None).unwrap_err();
        assert!(err.contains("E-OSCAL-018"));
    }

    #[test]
    fn test_poam_deterministic_uuid_stability() {
        let u1 = compute_poam_item_uuid("si-7(1)", "lean4", "test_si7", "sorry_axiom");
        let u2 = compute_poam_item_uuid("SI-7(1)", "LEAN4", "test_si7", "sorry_axiom");
        assert_eq!(
            u1, u2,
            "UUIDv5 must be case-insensitive on canonical control and source kind"
        );
    }

    #[test]
    fn test_poam_risk_accepted_requires_evidence_citation() {
        let err =
            validate_poam_transition(PoamState::Open, PoamState::RiskAccepted, None).unwrap_err();
        assert!(err.contains("E-OSCAL-018"));
        assert!(err.contains("requires a non-empty evidence citation"));

        assert!(validate_poam_transition(
            PoamState::Open,
            PoamState::RiskAccepted,
            Some("Waiver signed by CISO under policy section 4.2")
        )
        .is_ok());
    }

    #[test]
    fn test_poam_reopen_accumulates_history_with_same_id() {
        let now = Utc::now();
        let defect = PoamDefectInput {
            canonical_control_id: "si-7".to_string(),
            source_kind: "lean4".to_string(),
            source_id: "verify_kernel".to_string(),
            finding_category: "sorry_axiom".to_string(),
            title: "Lean 4 sorry obligation in SI-7".to_string(),
            description: "Proof incomplete".to_string(),
            finding_uuid: Some(Uuid::new_v4()),
            observation_uuid: Some(Uuid::new_v4()),
            activity_uuid: Some(Uuid::new_v4()),
            implementation_statement_uuid: Some(Uuid::new_v4()),
            remediation_deadline: Some(now + chrono::Duration::days(14)),
            initial_state: Some(PoamState::Open),
            evidence_citation: None,
        };

        // 1. Initial defect discovery
        let (doc1, out1) = sync_poam_state(None, std::slice::from_ref(&defect), now, None).unwrap();
        assert_eq!(out1.new_items.len(), 1);
        let defect_uuid = out1.new_items[0];
        assert_eq!(
            doc1.plan_of_action_and_milestones.poam_items[0].uuid,
            defect_uuid
        );

        // 2. Defect resolved in next pass (zero defects)
        let later = now + chrono::Duration::days(1);
        let (doc2, out2) = sync_poam_state(Some(&doc1), &[], later, None).unwrap();
        assert_eq!(out2.resolved_items.len(), 1);
        assert_eq!(out2.resolved_items[0], defect_uuid);
        let resolved_item = &doc2.plan_of_action_and_milestones.poam_items[0];
        assert_eq!(
            resolved_item
                .props
                .iter()
                .find(|p| p.name == "status")
                .unwrap()
                .value,
            "closed"
        );

        // 3. Defect regresses later: re-opened with EXACT SAME UUIDv5
        let much_later = now + chrono::Duration::days(5);
        let (doc3, out3) = sync_poam_state(Some(&doc2), &[defect], much_later, None).unwrap();
        assert_eq!(out3.reopened_items.len(), 1);
        assert_eq!(out3.reopened_items[0], defect_uuid);
        let reopened_item = &doc3.plan_of_action_and_milestones.poam_items[0];
        assert_eq!(
            reopened_item.uuid, defect_uuid,
            "Reopened item must keep exact same UUIDv5"
        );
        assert_eq!(
            reopened_item
                .props
                .iter()
                .find(|p| p.name == "status")
                .unwrap()
                .value,
            "open"
        );

        // Verify transition history accumulated in props
        let history_props: Vec<_> = reopened_item
            .props
            .iter()
            .filter(|p| p.name == "transition-event")
            .collect();
        // 1 initial + 1 closed + 1 reopened = 3 transition events
        assert_eq!(history_props.len(), 3);
    }

    #[test]
    fn test_poam_caps_and_overdue_enforcement() {
        let now = Utc::now();
        let past_deadline = now - chrono::Duration::days(2);
        let defect = PoamDefectInput {
            canonical_control_id: "au-3".to_string(),
            source_kind: "test".to_string(),
            source_id: "audit_logger".to_string(),
            finding_category: "coverage".to_string(),
            title: "AU-3 Coverage Failure".to_string(),
            description: "Audit logger test failed".to_string(),
            finding_uuid: None,
            observation_uuid: None,
            activity_uuid: None,
            implementation_statement_uuid: None,
            remediation_deadline: Some(past_deadline),
            initial_state: Some(PoamState::Open),
            evidence_citation: None,
        };

        let caps = PoamCapsConfig {
            max_open_items: Some(0), // Cap = 0, should fail
            fail_on_overdue: true,
        };

        let (_doc, out) = sync_poam_state(None, &[defect], now, Some(&caps)).unwrap();
        assert_eq!(out.active_open_count, 1);
        assert_eq!(out.overdue_items.len(), 1);
        assert!(out
            .violations
            .iter()
            .any(|v| v.contains("exceeds policy cap")));
        assert!(out
            .violations
            .iter()
            .any(|v| v.contains("exceeded remediation deadline")));
    }
}
