# Repository workflow

- Work on a feature branch for every upgrade. Do not commit changes directly to `main` or `master`.
- Continue an existing suitable feature branch; use the `codex/` prefix when creating a new branch.
- Preserve the original recovery tag `pre-improvements-2026-11-01` and existing checkpoints.
- Verify the change, save a checkpoint, and prepare a pull request against `main` when the work is ready for review. Do not merge the PR unless the user requests it.
- Preserve the existing Apple-style glassmorphism design and page layouts. Functional corrections and accurate state/error displays should use the established visual components.
- Keep private environment files, raw traffic logs, captures, datasets, and serialized model binaries out of Git. Evaluation summaries may be committed when they contain no private flow records.
- Describe evaluation scope precisely: CSV benchmark results, shadow observations, and labeled live detection performance are different measurements.
