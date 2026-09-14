"""Detection pipeline: normalize raw ZAP output into contract-shaped detection records.

Modules here are pure and fixture-testable (FR-N1/N2, FR-X1, FR-L1/L2): they operate on
JSON in / JSON out with no dependency on a running scanner. The single source of truth for
shapes and the fingerprint formula is `contracts/` — code is written *to* those files.
"""
