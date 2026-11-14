# oscal-diagnostics

## Executive Summary
`oscal-diagnostics` provides compiler-style, structured diagnostic rendering and error reporting for the PRIME framework. It translates compliance failures, schema violations, and gate rejections into precise, annotated error reports utilizing `annotate-snippets`, mapping error codes to deterministic remediation paths.

## Mathematical Overview
Let a diagnostic reporting mapping be defined as:
$$\Delta: \mathcal{E} \times \mathcal{S} \to \text{RenderedOutput}$$
where $\mathcal{E}$ is the set of structured error structures carrying error codes (e.g. `PP5404`), and $\mathcal{S}$ is the source mapping or schema coordinate space. Each error code $e_i \in \mathcal{E}$ corresponds to a bijection with a formal invariant violation in the conformance lattice:
$$\forall e_i, \quad \exists ! \, \psi_i \in \text{Invariants} \quad \text{s.t.} \quad \text{Violation}(\psi_i) \iff \text{Emit}(e_i)$$

## Implications
- **Deterministic Diagnostics**: Ensures exact, machine-parseable error formatting across all host and target environments.
- **Audit Traceability**: Directly associates diagnostic output codes with normative requirements in `COMPLIANCE.md` and `ERRORS.md`.
- **Zero-Ambiguity Failures**: Eliminates vague runtime warnings in favor of definitive compliance refutations.
