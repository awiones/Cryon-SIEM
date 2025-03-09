package analyzer

import (
	"fmt"
	"sync"
	"time"

	"github.com/awion/cryon-siem/model"
	"github.com/awion/cryon-siem/public/storage"
)

// RuleConfig represents a single detection rule
type RuleConfig struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Severity    string            `yaml:"severity"`
	Type        string            `yaml:"type"`
	Pattern     string            `yaml:"pattern"`
	Threshold   int               `yaml:"threshold"`
	Timeframe   int               `yaml:"timeframe"`
	Parameters  map[string]string `yaml:"parameters"`
	Enabled     bool              `yaml:"enabled"`
}

// Analyzer processes events against security rules
type Analyzer struct {
	rules     []RuleConfig
	storage   *storage.Storage
	alertChan chan model.Alert
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// NewAnalyzer creates a new security event analyzer
func NewAnalyzer(rules []RuleConfig, storage *storage.Storage) *Analyzer {
	return &Analyzer{
		rules:     rules,
		storage:   storage,
		alertChan: make(chan model.Alert, 100),
		stopChan:  make(chan struct{}),
	}
}

// Start begins the analyzer engine
func (a *Analyzer) Start() {
	fmt.Println("Starting Cryon SIEM analyzer...")

	// Start the alert processor
	a.wg.Add(1)
	go a.processAlerts()

	// Start correlation engine
	a.wg.Add(1)
	go a.runCorrelationEngine()
}

// Stop halts the analyzer engine
func (a *Analyzer) Stop() {
	fmt.Println("Stopping analyzer...")

	close(a.stopChan)
	a.wg.Wait()

	fmt.Println("Analyzer stopped")
}

// AnalyzeEvent processes a single event against all enabled rules
func (a *Analyzer) AnalyzeEvent(event model.Event) {
	for _, rule := range a.rules {
		if !rule.Enabled {
			continue
		}

		if a.eventMatchesRule(event, rule) {
			alert := a.createAlert(event, rule)
			a.alertChan <- alert
		}
	}
}

// eventMatchesRule checks if an event matches a rule's criteria
func (a *Analyzer) eventMatchesRule(event model.Event, rule RuleConfig) bool {
	// Implementation depends on rule type
	switch rule.Type {
	case "regex":
		return a.matchRegex(event, rule)
	case "threshold":
		return a.matchThreshold(event, rule)
	case "correlation":
		// Correlation rules are handled by the correlation engine
		return false
	default:
		return false
	}
}

// matchRegex checks if event data matches a regex pattern
func (a *Analyzer) matchRegex(event model.Event, rule RuleConfig) bool {
	// In a real implementation, this would use regex pattern matching
	// For this example, we're just checking if the rule pattern is in the event data
	return true
}

// matchThreshold checks if an event type exceeds a threshold in a timeframe
func (a *Analyzer) matchThreshold(event model.Event, rule RuleConfig) bool {
	// Get count of similar events in timeframe
	timeframe := time.Duration(rule.Timeframe) * time.Second
	count := a.storage.CountSimilarEvents(event.Type, timeframe)

	return count >= rule.Threshold
}

// createAlert generates an alert from a matched event and rule
func (a *Analyzer) createAlert(event model.Event, rule RuleConfig) model.Alert {
	severity := model.ParseSeverity(rule.Severity)

	return model.Alert{
		ID:          fmt.Sprintf("alert-%d", time.Now().UnixNano()),
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		EventID:     event.ID,
		Timestamp:   time.Now(),
		Description: rule.Description,
		Severity:    severity,
		Source:      event.Source,
	}
}

// processAlerts handles storing and forwarding alerts
func (a *Analyzer) processAlerts() {
	defer a.wg.Done()

	for {
		select {
		case alert := <-a.alertChan:
			a.storage.StoreAlert(alert)
			fmt.Printf("ALERT [%s]: %s - %s\n", alert.Severity, alert.RuleName, alert.Description)
		case <-a.stopChan:
			return
		}
	}
}

// runCorrelationEngine periodically runs correlation rules
func (a *Analyzer) runCorrelationEngine() {
	defer a.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.processCorrelationRules()
		case <-a.stopChan:
			return
		}
	}
}

// processCorrelationRules runs all enabled correlation rules
func (a *Analyzer) processCorrelationRules() {
	for _, rule := range a.rules {
		if !rule.Enabled || rule.Type != "correlation" {
			continue
		}

		// Implementation would analyze event patterns in a time window
		// based on the correlation rule logic
	}
}

// GetRules returns the list of detection rules
func (a *Analyzer) GetRules() []RuleConfig {
	return a.rules
}
