#!/usr/bin/env bash
# Apply Niv.ON's GitHub security settings (idempotent). Requires: gh auth with repo scope.
set -euo pipefail
R="${1:-BryanParreira/niv-on}"

echo "• repo options + secret scanning + push protection"
gh api -X PATCH "repos/$R" --input - >/dev/null <<'JSON'
{"has_wiki": false, "allow_merge_commit": false, "delete_branch_on_merge": true,
 "security_and_analysis": {"secret_scanning": {"status": "enabled"},
                           "secret_scanning_push_protection": {"status": "enabled"}}}
JSON

echo "• Dependabot alerts, security fixes, private vulnerability reporting"
gh api -X PUT "repos/$R/vulnerability-alerts" >/dev/null
gh api -X PUT "repos/$R/automated-security-fixes" >/dev/null
gh api -X PUT "repos/$R/private-vulnerability-reporting" >/dev/null

echo "• Actions: read-only default token, cannot approve PRs"
gh api -X PUT "repos/$R/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false >/dev/null

echo "• 'release' environment, deployable only from v* tags"
gh api -X PUT "repos/$R/environments/release" --input - >/dev/null <<'JSON'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
if ! gh api "repos/$R/environments/release/deployment-branch-policies" --jq '.branch_policies[].name' | grep -qx 'v\*'; then
  gh api -X POST "repos/$R/environments/release/deployment-branch-policies" -f name='v*' -f type=tag >/dev/null
fi

echo "• rulesets: protect main, release tags admin-only"
existing="$(gh api "repos/$R/rulesets" --jq '.[].name')"
grep -qx protect-main <<<"$existing" || gh api -X POST "repos/$R/rulesets" --input - >/dev/null <<'JSON'
{"name": "protect-main", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
 "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]}
JSON
grep -qx protect-release-tags <<<"$existing" || gh api -X POST "repos/$R/rulesets" --input - >/dev/null <<'JSON'
{"name": "protect-release-tags", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
 "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
 "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}]}
JSON
echo "✓ $R hardened"
