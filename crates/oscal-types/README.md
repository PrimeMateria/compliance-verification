# oscal-types

## Executive Summary
`oscal-types` defines the foundational data structures, Rust type models, and serialization schemas for OSCAL (Open Security Controls Assessment Language) and PRIME authorization bundles (`.pcrate` manifests and evidence structures).

## Mathematical Overview
Let $\mathcal{U}$ be the universe of valid OSCAL documents and bundle manifests. `oscal-types` defines a data-type lattice $\langle D, \sqsubseteq \rangle$ with strict serialization mappings:
$$\text{Serialize}: D \to \text{JSON}, \quad \text{Deserialize}: \text{JSON} \to D_\bot$$
where deserialization is total and infallible on valid schema instances, mapping malformed inputs to an explicit bottom element $D_\bot$ (decoding error).

## Implications
- **Independent Consumption**: Usable by any Rust application requiring robust, type-safe OSCAL 1.1.0 data structures without coupling to the verification gate.
- **Strict Canonicalization**: Enforces deterministic serialization rules ensuring invariant object hashes and reproducible bundle fingerprints.
- **Backward Compatibility**: Maintains strict versioning guarantees for schema objects across major and minor releases.
