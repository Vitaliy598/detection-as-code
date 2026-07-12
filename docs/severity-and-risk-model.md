# Severity and risk model

Severity represents expected analyst urgency; risk score provides finer ordering inside that band.

| Severity | Risk range | Interpretation |
|---|---:|---|
| `low` | 1–39 | Weak or contextual signal; normally enrichment-first |
| `medium` | 40–69 | Suspicious behavior requiring timely review |
| `high` | 70–89 | Correlated behavior with material compromise potential |
| `critical` | 90–100 | High-confidence, high-impact chain requiring immediate action |

The lab keeps SSH/sudo/cron at risk 90 while severity remains `high`: impact is substantial, but critical severity requires environment confirmation not available in fixtures. Scores are documented engineering judgments, not calibrated probabilities.
