package model

import (
	"time"
)

// Severity represents the severity level of events and alerts
type Severity string

// Severity levels
const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ParseSeverity converts a string to a Severity type
func ParseSeverity(s string) Severity {
	switch s {
	case "CRITICAL", "critical":
		return SeverityCritical
	case "HIGH", "high":
		return SeverityHigh
	case "MEDIUM", "medium":
		return SeverityMedium
	case "LOW", "low":
		return SeverityLow
	case "INFO", "info":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// Event represents a security event
type Event struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	RawData     []byte                 `json:"raw_data,omitempty"`
	Severity    Severity               `json:"severity"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
}

// Alert represents a security alert generated from events
type Alert struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"ruleId"`
	RuleName    string                 `json:"ruleName"`
	EventID     string                 `json:"eventId"`
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Severity    Severity               `json:"severity"`
	Source      string                 `json:"source"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
	Data        map[string]interface{} `json:"data"`
}

// User represents a system user
type User struct {
	Username string    `json:"username"`
	FullName string    `json:"fullName"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"lastSeen,omitempty"`
}

// Audit represents an audit log entry for system actions
type Audit struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Success   bool      `json:"success"`
	Details   string    `json:"details,omitempty"`
}

// Rule represents a security rule
type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Type        string   `json:"type"`
	Pattern     string   `json:"pattern"`
	Enabled     bool     `json:"enabled"`
}
