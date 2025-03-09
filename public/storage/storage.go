package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/awion/cryon-siem/model"
)

// StorageConfig represents storage configuration options
type StorageConfig struct {
	Type     string `yaml:"type"`
	Path     string `yaml:"path"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

// Storage manages the persistence of events and alerts
type Storage struct {
	config       StorageConfig
	events       map[string]model.Event
	alerts       map[string]model.Alert
	processedIDs map[string]bool
	mutex        sync.RWMutex
}

// NewStorage initializes a new storage system based on configuration
func NewStorage(config StorageConfig) (*Storage, error) {
	var storage *Storage

	switch config.Type {
	case "memory":
		storage = &Storage{
			config:       config,
			events:       make(map[string]model.Event),
			alerts:       make(map[string]model.Alert),
			processedIDs: make(map[string]bool),
		}
	case "sqlite":
		// Implementation for SQLite storage
		return nil, fmt.Errorf("sqlite storage not implemented yet")
	case "postgres":
		// Implementation for PostgreSQL storage
		return nil, fmt.Errorf("postgres storage not implemented yet")
	default:
		return nil, fmt.Errorf("unknown storage type: %s", config.Type)
	}

	fmt.Printf("Initialized %s storage\n", config.Type)
	return storage, nil
}

// Close cleans up storage resources
func (s *Storage) Close() error {
	fmt.Println("Closing storage...")
	return nil
}

// StoreEvent persists an event
func (s *Storage) StoreEvent(event model.Event) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.events[event.ID] = event
}

// GetEvent retrieves an event by ID
func (s *Storage) GetEvent(id string) (model.Event, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	event, exists := s.events[id]
	return event, exists
}

// GetEvents retrieves events matching criteria
func (s *Storage) GetEvents(limit int) []model.Event {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	events := make([]model.Event, 0, limit)
	count := 0

	for _, event := range s.events {
		events = append(events, event)
		count++

		if count >= limit {
			break
		}
	}

	return events
}

// GetUnprocessedEvents retrieves events that haven't been analyzed
func (s *Storage) GetUnprocessedEvents(limit int) []model.Event {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	events := make([]model.Event, 0, limit)
	count := 0

	for id, event := range s.events {
		if !s.processedIDs[id] {
			events = append(events, event)
			count++
		}

		if count >= limit {
			break
		}
	}

	return events
}

// MarkEventProcessed marks an event as processed
func (s *Storage) MarkEventProcessed(id string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.processedIDs[id] = true
}

// CountSimilarEvents counts events of a certain type within a timeframe
func (s *Storage) CountSimilarEvents(eventType string, timeframe time.Duration) int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	count := 0
	cutoff := time.Now().Add(-timeframe)

	for _, event := range s.events {
		if event.Type == eventType && event.Timestamp.After(cutoff) {
			count++
		}
	}

	return count
}

// StoreAlert persists an alert
func (s *Storage) StoreAlert(alert model.Alert) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.alerts[alert.ID] = alert
}

// GetAlert retrieves an alert by ID
func (s *Storage) GetAlert(id string) (model.Alert, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	alert, exists := s.alerts[id]
	return alert, exists
}

// GetAlerts retrieves alerts matching criteria
func (s *Storage) GetAlerts(limit int) []model.Alert {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	alerts := make([]model.Alert, 0, limit)
	count := 0

	for _, alert := range s.alerts {
		alerts = append(alerts, alert)
		count++

		if count >= limit {
			break
		}
	}

	return alerts
}
