# StegTVC Core v1.0

Runtime API and AI routing layer for the StegVerse Token Vault (TV).

- **TV repo**: holds policy, roles, issuers, OPA rules.
- **StegTVC**: loads a bundle exported from TV and exposes:
  - `/health` – status with bundle version
  - `/config/status` – bundle path + integrity
  - `/tokens/issue` – issues StegVerse JWT tokens
  - `/ai/route` – routes AI calls (initially via GitHub Models)

## 1. Getting the policy bundle

In the `StegVerse/TV` repo:

1. Use the exporter script to create `exports/stegtv_policy_bundle.json`.
2. Copy that file into this repo as `policy_bundle.json`.

Or set the env var `STEGTV_POLICY_BUNDLE_PATH` to point at the bundle.

## 2. Environment variables

- `STEGTV_POLICY_BUNDLE_PATH` – optional, default: `./policy_bundle.json`
- `STEGTV_JWT_SECRET` – secret used to sign issued tokens
- `GITHUB_MODELS_TOKEN` – PAT with access to GitHub Models billing

## 3. Run locally

```bash
pip install -r requirements.txt
export STEGTV_JWT_SECRET="replace-me"
export GITHUB_MODELS_TOKEN="ghp_..."
uvicorn app.main:app --reload --port 8000
```
