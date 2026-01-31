package rbac

import (
	"testing"
)

// AuthPolicy Tests

func TestNewAuthPolicy(t *testing.T) {
	name := "admin-policy"
	permissions := []string{"read", "write", "delete"}

	policy := NewAuthPolicy(name, permissions)

	if policy.Name != name {
		t.Errorf("Policy name mismatch: got %v, want %v", policy.Name, name)
	}
	if len(policy.RequiredPermissions) != len(permissions) {
		t.Errorf("Policy permissions length mismatch: got %v, want %v", len(policy.RequiredPermissions), len(permissions))
	}
}

func TestAuthPolicy_IsAllowed_AllPermissionsPresent(t *testing.T) {
	policy := NewAuthPolicy("test-policy", []string{"read", "write"})
	userPermissions := []string{"read", "write", "delete"}

	if !policy.IsAllowed(userPermissions) {
		t.Error("IsAllowed() should return true when user has all required permissions")
	}
}

func TestAuthPolicy_IsAllowed_MissingPermission(t *testing.T) {
	policy := NewAuthPolicy("test-policy", []string{"read", "write", "delete"})
	userPermissions := []string{"read", "write"}

	if policy.IsAllowed(userPermissions) {
		t.Error("IsAllowed() should return false when user is missing required permissions")
	}
}

func TestAuthPolicy_IsAllowed_EmptyRequired(t *testing.T) {
	policy := NewAuthPolicy("test-policy", []string{})
	userPermissions := []string{"read", "write"}

	if !policy.IsAllowed(userPermissions) {
		t.Error("IsAllowed() should return true when no permissions are required")
	}
}

func TestAuthPolicy_IsAllowed_EmptyUserPerms(t *testing.T) {
	policy := NewAuthPolicy("test-policy", []string{"read", "write"})
	userPermissions := []string{}

	if policy.IsAllowed(userPermissions) {
		t.Error("IsAllowed() should return false when user has no permissions but policy requires some")
	}
}

func TestAuthPolicy_IsAllowed_ExtraPermissions(t *testing.T) {
	policy := NewAuthPolicy("test-policy", []string{"read"})
	userPermissions := []string{"read", "write", "delete", "admin", "superuser"}

	if !policy.IsAllowed(userPermissions) {
		t.Error("IsAllowed() should return true when user has required permissions plus extras")
	}
}

func TestAuthPolicy_IsAllowed_ExactMatch(t *testing.T) {
	policy := NewAuthPolicy("test-policy", []string{"read", "write"})
	userPermissions := []string{"read", "write"}

	if !policy.IsAllowed(userPermissions) {
		t.Error("IsAllowed() should return true when user has exactly the required permissions")
	}
}

// AuthPolicyHandler Tests

func TestNewAuthPolicyHandler(t *testing.T) {
	handler := NewAuthPolicyHandler()

	if handler == nil {
		t.Fatal("NewAuthPolicyHandler() returned nil")
	}
	if handler.policies == nil {
		t.Fatal("NewAuthPolicyHandler() policies map is nil")
	}
	if len(handler.policies) != 0 {
		t.Error("NewAuthPolicyHandler() should create empty policies map")
	}
}

func TestAddPolicy(t *testing.T) {
	handler := NewAuthPolicyHandler()
	policy := NewAuthPolicy("test-policy", []string{"read", "write"})

	handler.AddPolicy(policy)

	if len(handler.policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(handler.policies))
	}

	storedPolicy, exists := handler.policies["test-policy"]
	if !exists {
		t.Error("Policy was not stored in handler")
	}
	if storedPolicy.Name != policy.Name {
		t.Errorf("Stored policy name mismatch: got %v, want %v", storedPolicy.Name, policy.Name)
	}
}

func TestAddPolicy_Multiple(t *testing.T) {
	handler := NewAuthPolicyHandler()
	policy1 := NewAuthPolicy("policy-1", []string{"read"})
	policy2 := NewAuthPolicy("policy-2", []string{"write"})
	policy3 := NewAuthPolicy("policy-3", []string{"delete"})

	handler.AddPolicy(policy1)
	handler.AddPolicy(policy2)
	handler.AddPolicy(policy3)

	if len(handler.policies) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(handler.policies))
	}
}

func TestAddPolicy_Overwrite(t *testing.T) {
	handler := NewAuthPolicyHandler()
	policy1 := NewAuthPolicy("test-policy", []string{"read"})
	policy2 := NewAuthPolicy("test-policy", []string{"write", "delete"})

	handler.AddPolicy(policy1)
	handler.AddPolicy(policy2)

	if len(handler.policies) != 1 {
		t.Errorf("Expected 1 policy (overwritten), got %d", len(handler.policies))
	}

	storedPolicy, _ := handler.policies["test-policy"]
	if len(storedPolicy.RequiredPermissions) != 2 {
		t.Error("Policy should have been overwritten with new permissions")
	}
}

func TestGetPolicy_Exists(t *testing.T) {
	handler := NewAuthPolicyHandler()
	policy := NewAuthPolicy("test-policy", []string{"read", "write"})
	handler.AddPolicy(policy)

	retrievedPolicy, exists := handler.GetPolicy("test-policy")

	if !exists {
		t.Error("GetPolicy() should return true for existing policy")
	}
	if retrievedPolicy.Name != policy.Name {
		t.Errorf("Retrieved policy name mismatch: got %v, want %v", retrievedPolicy.Name, policy.Name)
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	handler := NewAuthPolicyHandler()

	_, exists := handler.GetPolicy("non-existent-policy")

	if exists {
		t.Error("GetPolicy() should return false for non-existent policy")
	}
}

func TestListPolicies(t *testing.T) {
	handler := NewAuthPolicyHandler()
	policy1 := NewAuthPolicy("policy-1", []string{"read"})
	policy2 := NewAuthPolicy("policy-2", []string{"write"})
	policy3 := NewAuthPolicy("policy-3", []string{"delete"})

	handler.AddPolicy(policy1)
	handler.AddPolicy(policy2)
	handler.AddPolicy(policy3)

	policies := handler.ListPolicies()

	if len(policies) != 3 {
		t.Errorf("ListPolicies() returned %d policies, want 3", len(policies))
	}

	// Check that all policies are present (order doesn't matter)
	policyNames := make(map[string]bool)
	for _, p := range policies {
		policyNames[p.Name] = true
	}

	if !policyNames["policy-1"] || !policyNames["policy-2"] || !policyNames["policy-3"] {
		t.Error("ListPolicies() did not return all expected policies")
	}
}

func TestListPolicies_Empty(t *testing.T) {
	handler := NewAuthPolicyHandler()

	policies := handler.ListPolicies()

	if len(policies) != 0 {
		t.Errorf("ListPolicies() on empty handler returned %d policies, want 0", len(policies))
	}
}

func TestRemovePolicy(t *testing.T) {
	handler := NewAuthPolicyHandler()
	policy := NewAuthPolicy("test-policy", []string{"read", "write"})
	handler.AddPolicy(policy)

	handler.RemovePolicy("test-policy")

	if len(handler.policies) != 0 {
		t.Errorf("Expected 0 policies after removal, got %d", len(handler.policies))
	}

	_, exists := handler.GetPolicy("test-policy")
	if exists {
		t.Error("Policy should not exist after removal")
	}
}

func TestRemovePolicy_NotFound(t *testing.T) {
	handler := NewAuthPolicyHandler()
	policy := NewAuthPolicy("test-policy", []string{"read", "write"})
	handler.AddPolicy(policy)

	// Should not panic when removing non-existent policy
	handler.RemovePolicy("non-existent-policy")

	if len(handler.policies) != 1 {
		t.Errorf("Expected 1 policy (unaffected), got %d", len(handler.policies))
	}
}

func TestClearPolicies(t *testing.T) {
	handler := NewAuthPolicyHandler()
	policy1 := NewAuthPolicy("policy-1", []string{"read"})
	policy2 := NewAuthPolicy("policy-2", []string{"write"})
	policy3 := NewAuthPolicy("policy-3", []string{"delete"})

	handler.AddPolicy(policy1)
	handler.AddPolicy(policy2)
	handler.AddPolicy(policy3)

	handler.ClearPolicies()

	if len(handler.policies) != 0 {
		t.Errorf("Expected 0 policies after clear, got %d", len(handler.policies))
	}

	policies := handler.ListPolicies()
	if len(policies) != 0 {
		t.Error("ListPolicies() should return empty slice after clear")
	}
}

func TestClearPolicies_AlreadyEmpty(t *testing.T) {
	handler := NewAuthPolicyHandler()

	// Should not panic when clearing empty handler
	handler.ClearPolicies()

	if len(handler.policies) != 0 {
		t.Errorf("Expected 0 policies, got %d", len(handler.policies))
	}
}
