use crate::error::{ProxyError, ProxyResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub user_id: String,
    pub resource: String,
    pub action: String,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub required_permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub resource_pattern: String,
    pub actions: Vec<String>,
    pub conditions: Vec<Condition>,
    pub effect: Effect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub attribute: String,
    pub operator: Operator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operator {
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
}

pub struct PolicyEngine {
    policies: Vec<Policy>,
    default_deny: bool,
}

impl PolicyEngine {
    pub fn new(default_deny: bool) -> Self {
        Self {
            policies: Vec::new(),
            default_deny,
        }
    }

    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }

    pub fn evaluate(&self, context: &PolicyContext) -> ProxyResult<PolicyDecision> {
        // Find all matching policies
        let mut allow_found = false;
        let mut deny_found = false;
        let mut reasons = Vec::new();

        for policy in &self.policies {
            for rule in &policy.rules {
                if self.matches_resource(&rule.resource_pattern, &context.resource)
                    && rule.actions.contains(&context.action)
                {
                    // Check conditions
                    if self.evaluate_conditions(&rule.conditions, &context.attributes) {
                        match rule.effect {
                            Effect::Allow => {
                                allow_found = true;
                                reasons.push(format!("Allowed by policy: {}", policy.name));
                            }
                            Effect::Deny => {
                                deny_found = true;
                                reasons.push(format!("Denied by policy: {}", policy.name));
                            }
                        }
                    }
                }
            }
        }

        // Deny takes precedence
        if deny_found {
            return Ok(PolicyDecision {
                allowed: false,
                reason: reasons.join("; "),
                required_permissions: vec![],
            });
        }

        if allow_found {
            return Ok(PolicyDecision {
                allowed: true,
                reason: reasons.join("; "),
                required_permissions: vec![],
            });
        }

        // Default decision
        if self.default_deny {
            Ok(PolicyDecision {
                allowed: false,
                reason: "No matching policy - default deny".to_string(),
                required_permissions: vec![],
            })
        } else {
            Ok(PolicyDecision {
                allowed: true,
                reason: "No matching policy - default allow".to_string(),
                required_permissions: vec![],
            })
        }
    }

    fn matches_resource(&self, pattern: &str, resource: &str) -> bool {
        // Simple wildcard matching
        if pattern == "*" {
            return true;
        }

        if pattern.ends_with("*") {
            let prefix = &pattern[..pattern.len() - 1];
            return resource.starts_with(prefix);
        }

        pattern == resource
    }

    fn evaluate_conditions(
        &self,
        conditions: &[Condition],
        attributes: &HashMap<String, String>,
    ) -> bool {
        for condition in conditions {
            if let Some(attr_value) = attributes.get(&condition.attribute) {
                let matches = match condition.operator {
                    Operator::Equals => attr_value == &condition.value,
                    Operator::NotEquals => attr_value != &condition.value,
                    Operator::Contains => attr_value.contains(&condition.value),
                    Operator::GreaterThan => {
                        attr_value.parse::<f64>().unwrap_or(0.0)
                            > condition.value.parse::<f64>().unwrap_or(0.0)
                    }
                    Operator::LessThan => {
                        attr_value.parse::<f64>().unwrap_or(0.0)
                            < condition.value.parse::<f64>().unwrap_or(0.0)
                    }
                };

                if !matches {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_evaluation_allow() {
        let mut engine = PolicyEngine::new(true);
        
        let policy = Policy {
            id: "policy1".to_string(),
            name: "Allow Read".to_string(),
            description: "Allow read access".to_string(),
            rules: vec![PolicyRule {
                resource_pattern: "/api/*".to_string(),
                actions: vec!["read".to_string()],
                conditions: vec![],
                effect: Effect::Allow,
            }],
        };

        engine.add_policy(policy);

        let context = PolicyContext {
            user_id: "user123".to_string(),
            resource: "/api/users".to_string(),
            action: "read".to_string(),
            attributes: HashMap::new(),
        };

        let decision = engine.evaluate(&context).unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn test_policy_evaluation_deny() {
        let mut engine = PolicyEngine::new(true);
        
        let policy = Policy {
            id: "policy1".to_string(),
            name: "Deny Delete".to_string(),
            description: "Deny delete access".to_string(),
            rules: vec![PolicyRule {
                resource_pattern: "/api/*".to_string(),
                actions: vec!["delete".to_string()],
                conditions: vec![],
                effect: Effect::Deny,
            }],
        };

        engine.add_policy(policy);

        let context = PolicyContext {
            user_id: "user123".to_string(),
            resource: "/api/users".to_string(),
            action: "delete".to_string(),
            attributes: HashMap::new(),
        };

        let decision = engine.evaluate(&context).unwrap();
        assert!(!decision.allowed);
    }
}
