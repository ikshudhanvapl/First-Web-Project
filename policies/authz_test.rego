# policies/authz_test.rego
# Run with: opa test policies/ --verbose

package nexus.authz_test

import data.nexus.authz

# ── Helpers ────────────────────────────────────────────────────────────────────

admin_input := {
    "user": {
        "id":          "user-001",
        "email":       "admin@nexus.local",
        "role":        "admin",
        "permissions": ["users:read", "users:write", "users:delete", "audit:read"],
        "status":      "ACTIVE",
    },
    "action":   "write",
    "resource": "users",
}

developer_input := {
    "user": {
        "id":          "user-002",
        "email":       "dev@nexus.local",
        "role":        "developer",
        "permissions": ["users:read"],
        "status":      "ACTIVE",
    },
    "action":   "read",
    "resource": "users",
}

suspended_input := {
    "user": {
        "id":          "user-003",
        "email":       "suspended@nexus.local",
        "role":        "manager",
        "permissions": ["users:read", "users:write"],
        "status":      "SUSPENDED",
    },
    "action":   "read",
    "resource": "users",
}

# ── Allow tests ────────────────────────────────────────────────────────────────

test_admin_allowed {
    authz.allow with input as admin_input
}

test_developer_read_allowed {
    authz.allow with input as developer_input
}

test_permission_string_match {
    authz.allow with input as {
        "user": {
            "id":          "user-010",
            "email":       "mgr@nexus.local",
            "role":        "manager",
            "permissions": ["users:read", "audit:read"],
            "status":      "ACTIVE",
        },
        "action":   "read",
        "resource": "audit",
    }
}

# ── Deny tests ─────────────────────────────────────────────────────────────────

test_developer_write_denied {
    not authz.allow with input as {
        "user": {
            "id":          "user-002",
            "email":       "dev@nexus.local",
            "role":        "developer",
            "permissions": ["users:read"],
            "status":      "ACTIVE",
        },
        "action":   "write",
        "resource": "users",
    }
}

test_suspended_user_denied {
    # Even though the user has permissions, the deny rule fires
    authz.deny with input as suspended_input
}

test_deprovisioned_user_denied {
    authz.deny with input as {
        "user": {
            "id":          "user-004",
            "email":       "ex@nexus.local",
            "role":        "admin",
            "permissions": ["users:read", "users:write", "users:delete"],
            "status":      "DEPROVISIONED",
        },
        "action":   "read",
        "resource": "users",
    }
}

test_no_permissions_denied {
    not authz.allow with input as {
        "user": {
            "id":          "user-005",
            "email":       "nobody@nexus.local",
            "role":        "contractor",
            "permissions": [],
            "status":      "ACTIVE",
        },
        "action":   "write",
        "resource": "users",
    }
}

# ── Self-service read ──────────────────────────────────────────────────────────

test_user_can_read_own_profile {
    authz.allow with input as {
        "user": {
            "id":          "user-006",
            "email":       "self@nexus.local",
            "role":        "contractor",
            "permissions": [],
            "status":      "ACTIVE",
        },
        "action":      "read",
        "resource":    "users",
        "resource_id": "user-006",   # same as user.id
    }
}

test_user_cannot_read_other_profile_without_permission {
    not authz.allow with input as {
        "user": {
            "id":          "user-006",
            "email":       "self@nexus.local",
            "role":        "contractor",
            "permissions": [],
            "status":      "ACTIVE",
        },
        "action":      "read",
        "resource":    "users",
        "resource_id": "user-007",   # different user
    }
}
