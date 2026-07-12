# Detection lifecycle

| State | Entry evidence | Exit criteria |
|---|---|---|
| `idea` | Behavior hypothesis and telemetry candidate | Use case and expected value documented |
| `development` | Initial rule and fixtures | Logic is reviewable and deterministic |
| `experimental` | Working tests | Required telemetry, limitations and ATT&CK rationale documented |
| `validation` | Semantic contract and regression tests pass | Boundary, benign and tuning tests pass; reviewer checklist complete |
| `production_candidate` | All repository gates pass | Environment owner accepts telemetry, performance and deployment plan |
| `tuning_required` | Measured drift or false-positive issue | Scoped change passes regression and expiry/rollback are defined |
| `deprecated` | Replacement or lost value documented | Consumers notified and removal date recorded |

The current main rules remain `validation`. `production_candidate` means only that repository-defined gates have passed. It does not mean production deployment, real-world validation or universal portability; environment-specific baselining, access control, performance testing and post-deployment monitoring remain outside this lab.
