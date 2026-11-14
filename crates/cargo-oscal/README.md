# cargo-oscal

## Executive Summary
`cargo-oscal` is the primary command-line interface and orchestrator for the PRIME verification and compliance framework. Operating as a standard Cargo subcommand (`cargo oscal`), it provisions pinned external verification toolchains (Kani, Charon, Lean/Lake, Trestle), orchestrates target-scoped evidence generation subprocesses across target triples, evaluates gate policies, and packages deterministic authorization bundles (`.pcrate`).

## Mathematical Overview
Let a workspace build request be modeled as a tuple $(C, T, E)$, where $C$ is the crate graph, $T \in \text{Triples}$ is the target architecture triple, and $E$ is the set of required evidence producers. 
The orchestrator defines a monotonic evaluation function:
$$\mathcal{G}(C, T, E) \to \text{Decisions} \in \{\text{Accept}, \text{Reject}\}$$
where $\mathcal{G}$ succeeds if and only if every control obligation $\phi \in \text{Controls}$ is satisfied by target-agnostic proofs (MIR/Lean) or target-specific evidence (tests, Miri, WASM sandboxes) bound to $T$:
$$\bigwedge_{\phi} \left( \text{Verified}(\phi, \text{target\_agnostic}) \lor \text{Verified}(\phi, T) \right)$$

## Implications
- **Ecosystem Integration**: Conforms strictly to standard Cargo subcommand conventions (`cargo install cargo-oscal`), decoupling tooling from rustc internals.
- **Target-Scoped Provenance**: Enforces separation between target-agnostic symbolic proofs (`evidence/target_agnostic/`) and target-specific runtime/sandbox evidence (`evidence/target_<triple>/`).
- **Fail-Closed Gate**: Guarantees that unverified or cross-target evidence pollution results in immediate build rejection.
