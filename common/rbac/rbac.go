package rbac

type AuthPolicy struct {
	Name                string
	RequiredPermissions []string
}

func NewAuthPolicy(name string, requiredPermissions []string) AuthPolicy {
	return AuthPolicy{
		Name:                name,
		RequiredPermissions: requiredPermissions,
	}
}

func (p *AuthPolicy) IsAllowed(permissions []string) bool {
	permissionSet := make(map[string]struct{})
	for _, perm := range permissions {
		permissionSet[perm] = struct{}{}
	}

	for _, reqPerm := range p.RequiredPermissions {
		if _, exists := permissionSet[reqPerm]; !exists {
			return false
		}
	}
	return true
}

type AuthPolicyHandler struct {
	policies map[string]AuthPolicy
}

func NewAuthPolicyHandler() *AuthPolicyHandler {
	return &AuthPolicyHandler{
		policies: make(map[string]AuthPolicy),
	}
}

func (h *AuthPolicyHandler) AddPolicy(policy AuthPolicy) {
	h.policies[policy.Name] = policy
}

func (h *AuthPolicyHandler) GetPolicy(name string) (AuthPolicy, bool) {
	policy, exists := h.policies[name]
	return policy, exists
}

func (h *AuthPolicyHandler) ListPolicies() []AuthPolicy {
	policies := make([]AuthPolicy, 0, len(h.policies))
	for _, policy := range h.policies {
		policies = append(policies, policy)
	}
	return policies
}

func (h *AuthPolicyHandler) RemovePolicy(name string) {
	delete(h.policies, name)
}

func (h *AuthPolicyHandler) ClearPolicies() {
	h.policies = make(map[string]AuthPolicy)
}
