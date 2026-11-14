# oscal-engine

## Executive Summary
`oscal-engine` is the core compliance and evidence synthesis library for PRIME. It implements gate evaluation algorithms, schema validation routines, and evidence tree construction, allowing embedding in downstream tooling and authorization pipelines without requiring the full CLI orchestrator.

## Mathematical Overview
Let an evidence bundle be represented as a directed acyclic graph $G = (V, E)$, where vertices $V$ represent evidence artifacts (MIR proofs, test runs, schema validations) and edges $E$ represent dependency relations. The engine evaluates the authorization predicate $\Pi$:
$$\Pi(G, \Omega) = \prod_{v \in V} \text{Valid}(v) \land \text{Satisfies}(v, \Omega)$$
where $\Omega$ is the normative security control baseline. The evaluation enforces monotonicity: adding unverified evidence never transitions the gate from `Reject` to `Accept`.

## Implications
- **Embeddable Verification**: Enables third-party services and IDEs to embed gate evaluation and evidence synthesis programmatically.
- **Strict Monotonicity**: Prevents unauthorized privilege escalation or evidence laundering through rigorous graph validation.
- **Standards Compliance**: Operates directly on standardized OSCAL 1.1.0 component definitions and custom `.pcrate` manifests.
