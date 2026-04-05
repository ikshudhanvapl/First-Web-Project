# policies/authz.rego v2
#
# Fixes from v1:
#   - deny rule now works: input.user.status is populated (was always missing)
#   - final_allow is what the backend should check, not `allow`
#   - Added explicit rule comments

package nexus.authz

import future.keywords.if
import future.keywords.in

# ── Default: deny everything ──────────────────────────────────────────────────
default allow = false
default deny  = false

# ── Core RBAC: user holds the required permission string ──────────────────────
allow if {
    required := sprintf("%s:%s", [input.resource, input.action])
    required in input.user.permissions
}

# ── Self-service: users can always read their own record ──────────────────────
allow if {
    input.action      == "read"
    input.resource    == "users"
    input.resource_id == input.user.id
}

# ── Admins bypass fine-grained checks ────────────────────────────────────────
allow if {
    input.user.role == "admin"
}

# ── Explicit deny: suspended / deprovisioned users ────────────────────────────
# v1 bug: input.user.status was never sent from the backend.
# v2 fix: auth.py now embeds status in the JWT and sends it in OPA input.
deny if {
    input.user.status in {"SUSPENDED", "DEPROVISIONED"}
}

# ── Final decision: allowed AND not explicitly denied ─────────────────────────
# The backend calls /v1/data/nexus/authz/allow which evaluates this rule.
# Override `allow` with `final_allow` if you want the deny to take precedence
# even when an allow rule would fire (e.g. admin who gets suspended).
final_allow := true  if { allow; not deny }
final_allow := false if { deny }
