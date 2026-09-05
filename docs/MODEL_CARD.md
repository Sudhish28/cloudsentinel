# Model card: synthetic-iforest-v1

## Intended use
Demonstrate an end-to-end anomaly inference pipeline for a portfolio project. Findings support human triage. Do not use scores to automatically disable accounts or assert compromise.

## Training data and reproducibility
1,000 synthetic rows generated with seed 42. UTC hours are uniformly sampled from 08:00–18:00, transfer sizes from 100–100,000 bytes, and failures occur with probability 0.02. No real user data is used.

Four features: sine and cosine of UTC hour, log1p(bytes transferred), and a failed-operation flag. Isolation Forest uses 100 estimators, contamination 0.03, and random_state 42. The version string identifies this synthetic recipe; dependency versions are pinned separately.

## Outputs
decision_function < 0 triggers an ML finding. The displayed score is clamp(50 - 200 × decision_function, 0, 100). This scaling is for ranking only; 80 does not mean an 80% chance of an attack.

Rules add independent evidence with their own severity. Unusual actions can be legitimate; normal-looking attacks can be missed.

## Evaluation and limitations
Automated tests verify deterministic inference and score bounds, not detection accuracy. No accuracy, precision, recall, or false-positive claim is made. The synthetic distribution is intentionally simple and is unsuitable as a real cloud baseline. Features do not include identity history, API category, working calendars, IP reputation, or resource sensitivity.

For meaningful evaluation, collect approved representative data, split chronologically with no identity/event leakage, fit preprocessing and model only on training data, then measure precision/recall, PR-AUC, false alerts per identity per day, and analyst review burden on held-out labeled incidents. Compare rules-only, ML-only, and combined results. Record provenance, thresholds, model version, and temporal drift. Tune only on validation data.

## Privacy
Event identifiers, principal, IP, and optional coordinates are stored in the database. The summary path forwards only action and generated findings; there is no raw-log prompt. Action strings remain untrusted. Retention, encryption policy, and access-control requirements must be implemented for a real deployment.
