//! Gate Rule & Witness Bijection Registry Module
//! Implements ADR-0016 / Milestone 6 Nine-Point Remediation and Falsifiability Registry

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Pinned schema version contract
pub const REGISTRY_SCHEMA_VERSION_CONTRACT: &str = "2.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateRuleRegistry {
    pub registry_meta: RegistryMeta,
    #[serde(default)]
    pub fixtures: BTreeMap<String, FixtureDefinition>,
    #[serde(default)]
    pub formal_kernel_witnesses: BTreeMap<String, FormalKernelWitness>,
    #[serde(default)]
    pub kernel_sensitivity_witnesses: BTreeMap<String, KernelSensitivityWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryMeta {
    pub schema_version: String,
    pub registry_version: String,
    pub discipline_mode: String,
    pub min_rejected_witnesses_per_control: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixtureDefinition {
    pub control_id: String,
    pub description: String,
    pub fixture_path: String,
    pub target_tool: String,
    pub trigger_rule_id: String,
    pub fixture_diagnostic_kind: String,
    pub policy_engine_fired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormalKernelWitness {
    pub control_id: String,
    pub target_theorem: String,
    pub target_tool: String,
    pub source_path: String,
    pub witness_path: String,
    pub theorem_ast_sha256: String,
    pub witness_module_sha256: String,
    pub witness_expected_outcome: String,
    pub witness_required_rejection_kind: String,
    pub mutation_recipe: MutationRecipe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelSensitivityWitness {
    pub control_id: String,
    pub target_theorem: String,
    pub target_tool: String,
    pub source_path: String,
    pub witness_path: String,
    pub theorem_ast_sha256: String,
    pub witness_module_sha256: String,
    pub witness_expected_outcome: String,
    pub mutation_recipe: MutationRecipe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationRecipe {
    pub strategy: String,
    pub target_symbol: String,
    pub target_position: String,
    pub params: BTreeMap<String, String>,
}

/// Allowlist of tool-to-diagnostic kind pairings
pub const LEAN4_REJECTION_KINDS: &[&str] = &["type_mismatch", "unknown_constant", "kernel_rejected"];
pub const KANI_REJECTION_KINDS: &[&str] = &["kani_unwind_overflow", "kani_assertion_failed"];

/// Permitted structural mutation strategies (negate_conclusion is strictly forbidden per ADR-0016)
pub const ALLOWED_MUTATION_STRATEGIES: &[&str] = &[
    "mutate_constant",
    "weaken_precondition",
    "strengthen_postcondition",
    "swap_equality_direction",
];

/// Valid directional relational operator inversion pairs for swap_equality_direction
/// Note: '=' and '!=' are strictly excluded because '=' -> '!=' is negation, not directional inversion.
pub const VALID_OPERATOR_INVERSION_PAIRS: &[(&str, &str)] = &[
    ("<=", ">="),
    (">=", "<="),
    ("<", ">"),
    (">", "<"),
];

/// Valid target positions within a theorem
pub const VALID_TARGET_POSITIONS: &[&str] = &["precondition", "postcondition"];

/// Thorough semantic validation of GateRuleRegistry per Milestone 6 specifications
pub fn verify_gate_rule_registry_semantics(reg: &GateRuleRegistry) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // 1. Residual 1: schema_version contract vs registry_version content revision
    if reg.registry_meta.schema_version != REGISTRY_SCHEMA_VERSION_CONTRACT {
        errors.push(format!(
            "Registry schema_version mismatch: expected '{}', found '{}'",
            REGISTRY_SCHEMA_VERSION_CONTRACT, reg.registry_meta.schema_version
        ));
    }
    if reg.registry_meta.registry_version.trim().is_empty() {
        errors.push("Registry registry_version cannot be empty".to_string());
    }

    // 2. Residual 2 & Item D: Fixtures validation (FX-08 diagnostic, trigger decoupling, and policy engine firing)
    for (fid, fix) in &reg.fixtures {
        if fid == "FX-08" {
            if fix.trigger_rule_id != "E-OSCAL-010" {
                errors.push(format!(
                    "FX-08 trigger_rule_id must be 'E-OSCAL-010', found '{}'",
                    fix.trigger_rule_id
                ));
            }
            if fix.fixture_diagnostic_kind != "no_tool_diagnostic" {
                errors.push(format!(
                    "FX-08 fixture_diagnostic_kind must be 'no_tool_diagnostic' (conflation of trigger with tool diagnostic is prohibited), found '{}'",
                    fix.fixture_diagnostic_kind
                ));
            }
            if !fix.policy_engine_fired {
                errors.push("FX-08 must declare policy_engine_fired = true (verification must assert that the policy engine actually fired)".to_string());
            }
            let fix_path = Path::new(&fix.fixture_path);
            let exists = fix_path.exists()
                || Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|root| root.join(fix_path))
                    .map(|p| p.exists())
                    .unwrap_or(false);
            if !exists {
                errors.push(format!("FX-08 fixture_path does not exist on disk: '{}'", fix.fixture_path));
            }
        }
    }

    // Track controls in formal_kernel_witnesses that have verified 'rejected' outcomes
    let mut control_rejected_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut sensitivity_controls: BTreeSet<String> = BTreeSet::new();

    // 3. Formal Kernel Witnesses Validation
    for (wid, w) in &reg.formal_kernel_witnesses {
        // Enforce W-[CONTROL]-[INDEX] naming pattern
        if !wid.starts_with("W-") {
            errors.push(format!("{}: Witness ID must start with 'W-', found '{}'", wid, wid));
        }

        // Must yield 'rejected' outcomes ONLY
        if w.witness_expected_outcome != "rejected" {
            errors.push(format!(
                "{}: formal_kernel_witnesses MUST declare witness_expected_outcome = 'rejected', found '{}'",
                wid, w.witness_expected_outcome
            ));
        } else {
            *control_rejected_counts.entry(w.control_id.clone()).or_insert(0) += 1;
        }

        // Check negate_conclusion elimination
        if w.mutation_recipe.strategy == "negate_conclusion" {
            errors.push(format!(
                "{}: 'negate_conclusion' is strictly forbidden in formal_kernel_witnesses (ADR-0016: negation of a Prop-trivial theorem is not a valid falsification)",
                wid
            ));
        } else if !ALLOWED_MUTATION_STRATEGIES.contains(&w.mutation_recipe.strategy.as_str()) {
            errors.push(format!(
                "{}: Unknown or disallowed mutation recipe strategy '{}'. Must be one of: {:?}",
                wid, w.mutation_recipe.strategy, ALLOWED_MUTATION_STRATEGIES
            ));
        }

        // Item A: Target position validation
        if !VALID_TARGET_POSITIONS.contains(&w.mutation_recipe.target_position.as_str()) {
            errors.push(format!(
                "{}: Invalid target_position '{}'. Must be 'precondition' or 'postcondition'",
                wid, w.mutation_recipe.target_position
            ));
        }

        if w.mutation_recipe.strategy == "weaken_precondition" && w.mutation_recipe.target_position != "precondition" {
            errors.push(format!(
                "{}: Strategy 'weaken_precondition' requires target_position = 'precondition', found '{}'",
                wid, w.mutation_recipe.target_position
            ));
        }
        if w.mutation_recipe.strategy == "strengthen_postcondition" && w.mutation_recipe.target_position != "postcondition" {
            errors.push(format!(
                "{}: Strategy 'strengthen_postcondition' requires target_position = 'postcondition', found '{}'",
                wid, w.mutation_recipe.target_position
            ));
        }

        // Clarification Check 1 & Item C: Recipe Parameter Validation Matrix & Primitive Literal Typing
        match w.mutation_recipe.strategy.as_str() {
            "mutate_constant" => {
                let orig = w.mutation_recipe.params.get("original");
                let muta = w.mutation_recipe.params.get("mutated");
                match (orig, muta) {
                    (Some(o), Some(m)) => {
                        let o_trimmed = o.trim();
                        let m_trimmed = m.trim();
                        if o_trimmed.is_empty() || m_trimmed.is_empty() {
                            errors.push(format!("{}: mutate_constant requires non-empty original and mutated params", wid));
                        } else {
                            // Enforce evaluated primitive literals of identical type (Item C)
                            let orig_i64 = o_trimmed.parse::<i64>();
                            let muta_i64 = m_trimmed.parse::<i64>();
                            let orig_f64 = o_trimmed.parse::<f64>();
                            let muta_f64 = m_trimmed.parse::<f64>();

                            let both_int = orig_i64.is_ok() && muta_i64.is_ok();
                            let both_float = orig_f64.is_ok() && muta_f64.is_ok() && (o_trimmed.contains('.') || m_trimmed.contains('.'));

                            if !both_int && !both_float {
                                errors.push(format!(
                                    "{}: mutate_constant requires evaluated primitive numeric literals of identical type (integers or floats). Expressions like '3^4' or non-literal strings are disallowed; found original='{}', mutated='{}'",
                                    wid, o, m
                                ));
                            }
                        }
                    }
                    _ => {
                        errors.push(format!("{}: mutate_constant requires 'original' and 'mutated' parameters", wid));
                    }
                }
            }
            "swap_equality_direction" => {
                let orig = w.mutation_recipe.params.get("original");
                let muta = w.mutation_recipe.params.get("mutated");
                match (orig, muta) {
                    (Some(o), Some(m)) => {
                        let is_valid_pair = VALID_OPERATOR_INVERSION_PAIRS
                            .iter()
                            .any(|(v_orig, v_muta)| v_orig == o && v_muta == m);
                        if !is_valid_pair {
                            errors.push(format!(
                                "{}: swap_equality_direction requires directional operator inversion pair (<=/<->>=/>). Equality '=' and '!=' are strictly disallowed as negation holes; found '{}' -> '{}'",
                                wid, o, m
                            ));
                        }
                    }
                    _ => {
                        errors.push(format!("{}: swap_equality_direction requires 'original' and 'mutated' operator parameters", wid));
                    }
                }
            }
            "weaken_precondition" | "strengthen_postcondition" => {
                if w.mutation_recipe.target_symbol.trim().is_empty() {
                    errors.push(format!("{}: {} requires a non-empty target_symbol", wid, w.mutation_recipe.strategy));
                }
                let orig = w.mutation_recipe.params.get("original");
                let muta = w.mutation_recipe.params.get("mutated");
                match (orig, muta) {
                    (Some(o), Some(m)) => {
                        if o.trim().is_empty() || m.trim().is_empty() {
                            errors.push(format!("{}: {} requires non-empty original and mutated transformation params", wid, w.mutation_recipe.strategy));
                        }
                    }
                    _ => {
                        errors.push(format!("{}: {} requires 'original' and 'mutated' parameters", wid, w.mutation_recipe.strategy));
                    }
                }
            }
            _ => {}
        }

        // Clarification Check 2: Tool-to-Diagnostic Allowlist Pairing
        match w.target_tool.as_str() {
            "lean4" => {
                if !LEAN4_REJECTION_KINDS.contains(&w.witness_required_rejection_kind.as_str()) {
                    errors.push(format!(
                        "{}: Target tool 'lean4' cannot use rejection kind '{}'. Allowed: {:?}",
                        wid, w.witness_required_rejection_kind, LEAN4_REJECTION_KINDS
                    ));
                }
            }
            "kani" => {
                if !KANI_REJECTION_KINDS.contains(&w.witness_required_rejection_kind.as_str()) {
                    errors.push(format!(
                        "{}: Target tool 'kani' cannot use rejection kind '{}'. Allowed: {:?}",
                        wid, w.witness_required_rejection_kind, KANI_REJECTION_KINDS
                    ));
                }
            }
            other => {
                errors.push(format!("{}: Unsupported target_tool '{}'", wid, other));
            }
        }
    }

    // 4. W-SI71-01 and W-SI71-02 specific assertions (Residual 3 & Item A / Item C)
    if let Some(w_si71_01) = reg.formal_kernel_witnesses.get("W-SI71-01") {
        if w_si71_01.mutation_recipe.target_position != "postcondition" {
            errors.push(format!(
                "W-SI71-01 target_position must be 'postcondition' (abs_bound is a conclusion bound on the third derivative estimator), found '{}'",
                w_si71_01.mutation_recipe.target_position
            ));
        }
    }

    if let Some(w_si71_02) = reg.formal_kernel_witnesses.get("W-SI71-02") {
        if w_si71_02.mutation_recipe.strategy != "mutate_constant" {
            errors.push(format!(
                "W-SI71-02 strategy must be 'mutate_constant' (array bounds mutation), found '{}'",
                w_si71_02.mutation_recipe.strategy
            ));
        }
        if w_si71_02.mutation_recipe.target_symbol != "patch_window_size" {
            errors.push(format!(
                "W-SI71-02 target_symbol must be 'patch_window_size', found '{}'",
                w_si71_02.mutation_recipe.target_symbol
            ));
        }
        if w_si71_02.mutation_recipe.target_position != "postcondition" {
            errors.push(format!(
                "W-SI71-02 target_position must be 'postcondition', found '{}'",
                w_si71_02.mutation_recipe.target_position
            ));
        }
        if w_si71_02.mutation_recipe.params.get("original") != Some(&"81".to_string())
            || w_si71_02.mutation_recipe.params.get("mutated") != Some(&"82".to_string())
        {
            errors.push(format!(
                "W-SI71-02 params must be normalized to evaluated literals original = '81', mutated = '82', found original='{:?}', mutated='{:?}'",
                w_si71_02.mutation_recipe.params.get("original"),
                w_si71_02.mutation_recipe.params.get("mutated")
            ));
        }
    }

    // 5. Kernel Sensitivity Witnesses Validation
    for (sid, s) in &reg.kernel_sensitivity_witnesses {
        if !sid.starts_with("S-") {
            errors.push(format!("{}: Sensitivity witness ID must start with 'S-', found '{}'", sid, sid));
        }
        sensitivity_controls.insert(s.control_id.clone());
    }

    // Clarification Check 3: Sensitivity Witness Exclusion from Bijection Evidence
    // Controls backed solely by sensitivity witnesses MUST fail with E-OSCAL-010
    let min_rejected = reg.registry_meta.min_rejected_witnesses_per_control;
    for ctrl in &sensitivity_controls {
        let rejected_count = control_rejected_counts.get(ctrl).copied().unwrap_or(0);
        if rejected_count < min_rejected {
            errors.push(format!(
                "[E-OSCAL-010] Control '{}' lacks required rejected falsifiability witness (has 0 rejected witnesses; sensitivity witnesses in kernel_sensitivity_witnesses do not count toward falsifiability coverage)",
                ctrl
            ));
        }
    }

    // Also check all formal kernel witness controls have at least min_rejected witnesses
    for (ctrl, count) in &control_rejected_counts {
        if *count < min_rejected {
            errors.push(format!(
                "[E-OSCAL-010] Control '{}' has only {} rejected witnesses, minimum required is {}",
                ctrl, count, min_rejected
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_gate_rule_registry_passes_validation() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let reg: GateRuleRegistry = toml::from_str(toml_str).expect("Canonical registry must parse as TOML");
        
        let val_result = verify_gate_rule_registry_semantics(&reg);
        assert!(val_result.is_ok(), "Canonical registry must pass semantic verification: {:?}", val_result);

        // Also test JSON Schema validation
        let val_json: serde_json::Value = serde_json::to_value(&reg).expect("Serialization to JSON Value");
        let schema_result = crate::validate_gate_rule_registry(&val_json);
        assert!(schema_result.is_ok(), "Canonical registry must validate against JSON schema: {:?}", schema_result);
    }

    #[test]
    fn test_residual_1_schema_version_mismatch_fails() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();
        reg.registry_meta.schema_version = "1.2.0".to_string();

        let res = verify_gate_rule_registry_semantics(&reg);
        assert!(res.is_err(), "Schema version mismatch must fail validation");
        let errs = res.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("Registry schema_version mismatch") && e.contains("expected '2.0.0'")));
    }

    #[test]
    fn test_residual_2_and_item_d_fx08_validation() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();

        // 1. Conflate tool diagnostic with policy trigger
        if let Some(fx) = reg.fixtures.get_mut("FX-08") {
            fx.fixture_diagnostic_kind = "type_mismatch".to_string();
        }
        let res1 = verify_gate_rule_registry_semantics(&reg);
        assert!(res1.unwrap_err().iter().any(|e| e.contains("no_tool_diagnostic")));

        // 2. Omit policy engine fired
        let mut reg2: GateRuleRegistry = toml::from_str(toml_str).unwrap();
        if let Some(fx) = reg2.fixtures.get_mut("FX-08") {
            fx.policy_engine_fired = false;
        }
        let res2 = verify_gate_rule_registry_semantics(&reg2);
        assert!(res2.unwrap_err().iter().any(|e| e.contains("policy_engine_fired = true")));
    }

    #[test]
    fn test_residual_3_and_item_c_w_si71_02_strategy_and_normalization() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();

        // 1. Declare weaken_precondition on constant mutation
        if let Some(w) = reg.formal_kernel_witnesses.get_mut("W-SI71-02") {
            w.mutation_recipe.strategy = "weaken_precondition".to_string();
        }
        let res1 = verify_gate_rule_registry_semantics(&reg);
        assert!(res1.unwrap_err().iter().any(|e| e.contains("W-SI71-02 strategy must be 'mutate_constant'")));

        // 2. Un-normalized expression "3^4" fails literal parse check
        let mut reg2: GateRuleRegistry = toml::from_str(toml_str).unwrap();
        if let Some(w) = reg2.formal_kernel_witnesses.get_mut("W-SI71-02") {
            w.mutation_recipe.params.insert("original".to_string(), "3^4".to_string());
            w.mutation_recipe.params.insert("mutated".to_string(), "3^4 + 1".to_string());
        }
        let res2 = verify_gate_rule_registry_semantics(&reg2);
        let errs2 = res2.unwrap_err();
        assert!(errs2.iter().any(|e| e.contains("requires evaluated primitive numeric literals") && e.contains("3^4")));
    }

    #[test]
    fn test_item_a_target_position_enforcement() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();

        // 1. Invalid target_position
        if let Some(w) = reg.formal_kernel_witnesses.get_mut("W-SI71-01") {
            w.mutation_recipe.target_position = "invalid_pos".to_string();
        }
        let res1 = verify_gate_rule_registry_semantics(&reg);
        assert!(res1.unwrap_err().iter().any(|e| e.contains("Invalid target_position")));

        // 2. Position mismatch for weaken_precondition
        let mut reg2: GateRuleRegistry = toml::from_str(toml_str).unwrap();
        if let Some(w) = reg2.formal_kernel_witnesses.get_mut("W-SI71-01") {
            w.mutation_recipe.strategy = "weaken_precondition".to_string();
            w.mutation_recipe.target_position = "postcondition".to_string();
        }
        let res2 = verify_gate_rule_registry_semantics(&reg2);
        assert!(res2.unwrap_err().iter().any(|e| e.contains("requires target_position = 'precondition'")));
    }

    #[test]
    fn test_item_b_equality_operator_swap_forbidden() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();

        // Attempt to smuggle '= -> !=' as swap_equality_direction (negation hole)
        if let Some(w) = reg.formal_kernel_witnesses.get_mut("W-SI71-01") {
            w.mutation_recipe.strategy = "swap_equality_direction".to_string();
            w.mutation_recipe.params.insert("original".to_string(), "=".to_string());
            w.mutation_recipe.params.insert("mutated".to_string(), "!=".to_string());
        }
        let res = verify_gate_rule_registry_semantics(&reg);
        assert!(res.is_err(), "'=' -> '!=' must be rejected as a negation hole");
        let errs = res.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("Equality '=' and '!=' are strictly disallowed as negation holes")));
    }

    #[test]
    fn test_negate_conclusion_strictly_forbidden_tautology_hole_closed() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();
        if let Some(w) = reg.formal_kernel_witnesses.get_mut("W-SI71-01") {
            w.mutation_recipe.strategy = "negate_conclusion".to_string();
        }

        let res = verify_gate_rule_registry_semantics(&reg);
        assert!(res.is_err(), "negate_conclusion must be rejected");
        let errs = res.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("strictly forbidden") && e.contains("ADR-0016")));
    }

    #[test]
    fn test_clarification_1_recipe_parameter_validation_matrix() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();
        // Test invalid operator pair
        if let Some(w) = reg.formal_kernel_witnesses.get_mut("W-SI71-01") {
            w.mutation_recipe.strategy = "swap_equality_direction".to_string();
            w.mutation_recipe.params.insert("original".to_string(), "<=".to_string());
            w.mutation_recipe.params.insert("mutated".to_string(), "invalid_op".to_string());
        }

        let res = verify_gate_rule_registry_semantics(&reg);
        assert!(res.is_err(), "Invalid operator pair must fail");
        let errs = res.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("directional operator inversion pair")));
    }

    #[test]
    fn test_clarification_2_tool_to_diagnostic_allowlist_pairing() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();
        if let Some(w) = reg.formal_kernel_witnesses.get_mut("W-SI71-01") {
            w.target_tool = "lean4".to_string();
            w.witness_required_rejection_kind = "kani_unwind_overflow".to_string();
        }

        let res = verify_gate_rule_registry_semantics(&reg);
        assert!(res.is_err(), "Mismatched tool diagnostic pairing must fail");
        let errs = res.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("cannot use rejection kind 'kani_unwind_overflow'")));
    }

    #[test]
    fn test_clarification_3_sensitivity_witnesses_excluded_from_bijection() {
        let toml_str = include_str!("../../../gate-rule-registry.toml");
        let mut reg: GateRuleRegistry = toml::from_str(toml_str).unwrap();
        reg.kernel_sensitivity_witnesses.insert(
            "S-AC2-01".to_string(),
            KernelSensitivityWitness {
                control_id: "AC-2".to_string(),
                target_theorem: "user_account_expiry".to_string(),
                target_tool: "lean4".to_string(),
                source_path: "source/lean/PRIME/Account.lean".to_string(),
                witness_path: "evidence/attestations/sensitivity/S_AC2_01.lean".to_string(),
                theorem_ast_sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                witness_module_sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                witness_expected_outcome: "proved".to_string(),
                mutation_recipe: MutationRecipe {
                    strategy: "strengthen_precondition".to_string(),
                    target_symbol: "session_timeout".to_string(),
                    target_position: "precondition".to_string(),
                    params: [("original".to_string(), "15".to_string()), ("mutated".to_string(), "10".to_string())].into_iter().collect(),
                },
            },
        );

        let res = verify_gate_rule_registry_semantics(&reg);
        assert!(res.is_err(), "Control with only proved sensitivity witness must fail E-OSCAL-010");
        let errs = res.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("[E-OSCAL-010]") && e.contains("AC-2") && e.contains("lacks required rejected falsifiability witness")));
    }
}
