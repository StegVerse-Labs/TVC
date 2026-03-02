# CATCH_UP.md (TVC)

## Current objective
Make StegTVC issue *ephemeral*, action-scoped StegVerse tokens (JWT) independent of GitHub.

## Today’s single task
Upgrade `/tokens/issue` to accept: action, scope, ttl_seconds, ctx_hash, bundle_hash, mode.
Issue a JWT with short exp + jti + act/scope/ctxh/bnd/mode/rev.

## Do not do today
- No PATs
- No GitHub Models tokens
- No workflow edits
- No deployments

## Next 3 steps after today
1) Add `/tokens/verify`
2) Add a tiny `sv_exec.py` wrapper that refuses to run without a valid token
3) Wire policy check (OPA) optional

## Notes
- Keep TTL <= 300 seconds for now.
