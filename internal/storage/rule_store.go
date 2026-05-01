package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RuleStore wraps DB and provides mail rule operations.
type RuleStore struct {
	DB *DB
}

// NewRuleStore returns a new RuleStore.
func NewRuleStore(db *DB) *RuleStore {
	return &RuleStore{DB: db}
}

// CreateRule inserts a new mail rule.
func (s *RuleStore) CreateRule(ctx context.Context, rule *MailRule) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO mail_rules (rule_id, user_id, tenant_id, name_encrypted, conditions_encrypted, actions_encrypted, enabled, priority)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		rule.RuleID, rule.UserID, rule.TenantID, rule.NameEncrypted, rule.ConditionsEncrypted, rule.ActionsEncrypted, rule.Enabled, rule.Priority,
	)
	if err != nil {
		return fmt.Errorf("create rule: %w", err)
	}
	return nil
}

// ListRules returns all rules for a user within a tenant.
func (s *RuleStore) ListRules(ctx context.Context, userID, tenantID uuid.UUID) ([]*MailRule, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT rule_id, user_id, tenant_id, name_encrypted, conditions_encrypted, actions_encrypted, enabled, priority, created_at
		 FROM mail_rules WHERE user_id = $1 AND tenant_id = $2 ORDER BY priority ASC`,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()

	var rules []*MailRule
	for rows.Next() {
		r := &MailRule{}
		if err := rows.Scan(&r.RuleID, &r.UserID, &r.TenantID, &r.NameEncrypted, &r.ConditionsEncrypted, &r.ActionsEncrypted, &r.Enabled, &r.Priority, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// GetRule retrieves a rule by ID.
func (s *RuleStore) GetRule(ctx context.Context, ruleID, userID, tenantID uuid.UUID) (*MailRule, error) {
	r := &MailRule{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT rule_id, user_id, tenant_id, name_encrypted, conditions_encrypted, actions_encrypted, enabled, priority, created_at
		 FROM mail_rules WHERE rule_id = $1 AND user_id = $2 AND tenant_id = $3`,
		ruleID, userID, tenantID,
	).Scan(&r.RuleID, &r.UserID, &r.TenantID, &r.NameEncrypted, &r.ConditionsEncrypted, &r.ActionsEncrypted, &r.Enabled, &r.Priority, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("rule not found: %s", ruleID)
	}
	if err != nil {
		return nil, fmt.Errorf("get rule: %w", err)
	}
	return r, nil
}

// UpdateRule updates a rule.
func (s *RuleStore) UpdateRule(ctx context.Context, rule *MailRule) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE mail_rules SET name_encrypted = $4, conditions_encrypted = $5, actions_encrypted = $6, enabled = $7, priority = $8
		 WHERE rule_id = $1 AND user_id = $2 AND tenant_id = $3`,
		rule.RuleID, rule.UserID, rule.TenantID, rule.NameEncrypted, rule.ConditionsEncrypted, rule.ActionsEncrypted, rule.Enabled, rule.Priority,
	)
	if err != nil {
		return fmt.Errorf("update rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("rule not found: %s", rule.RuleID)
	}
	return nil
}

// DeleteRule removes a rule.
func (s *RuleStore) DeleteRule(ctx context.Context, ruleID, userID, tenantID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM mail_rules WHERE rule_id = $1 AND user_id = $2 AND tenant_id = $3`,
		ruleID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("rule not found: %s", ruleID)
	}
	return nil
}
