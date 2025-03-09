package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/awion/cryon-siem/public/analyzer"
	"github.com/awion/cryon-siem/public/collector"
	"github.com/awion/cryon-siem/public/storage"
	"gopkg.in/yaml.v2"
)

// Config represents the application configuration
type Config struct {
	General struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Version     string `yaml:"version"`
	} `yaml:"general"`

	Logging struct {
		Level   string `yaml:"level"`
		File    string `yaml:"file"`
		Verbose bool   `yaml:"verbose"`
	} `yaml:"logging"`

	Storage storage.StorageConfig    `yaml:"storage"`
	Sources []collector.SourceConfig `yaml:"sources"`
	Rules   []analyzer.RuleConfig    `yaml:"rules"`

	Authentication struct {
		Enabled  bool   `yaml:"enabled"`
		Method   string `yaml:"method"`
		KeyFile  string `yaml:"keyFile"`
		CertFile string `yaml:"certFile"`
	} `yaml:"authentication"`

	API struct {
		Enabled bool   `yaml:"enabled"`
		Port    int    `yaml:"port"`
		TLS     bool   `yaml:"tls"`
		APIKey  string `yaml:"apiKey"`
	} `yaml:"api"`
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	// Get absolute file path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	// Check if file exists
	_, err = os.Stat(absPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file does not exist: %s", absPath)
	}

	// Read the file
	data, err := ioutil.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %v", err)
	}

	// Parse YAML
	config := &Config{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %v", err)
	}

	// Set defaults for missing values
	setDefaults(config)

	// Validate configuration
	err = validateConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	fmt.Printf("Loaded configuration from %s\n", absPath)
	return config, nil
}

// setDefaults fills in default values for missing configuration
func setDefaults(config *Config) {
	// General defaults
	if config.General.Name == "" {
		config.General.Name = "Cryon SIEM"
	}
	if config.General.Version == "" {
		config.General.Version = "0.1.0"
	}

	// Logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}

	// Storage defaults
	if config.Storage.Type == "" {
		config.Storage.Type = "memory"
	}

	// API defaults
	if config.API.Port == 0 {
		config.API.Port = 8080
	}
}

// validateConfig checks if the configuration is valid
func validateConfig(config *Config) error {
	// Validate storage configuration
	switch config.Storage.Type {
	case "memory":
		// No additional validation needed
	case "sqlite":
		if config.Storage.Path == "" {
			return fmt.Errorf("sqlite storage requires a path")
		}
	case "postgres":
		if config.Storage.Host == "" {
			return fmt.Errorf("postgres storage requires a host")
		}
		if config.Storage.Database == "" {
			return fmt.Errorf("postgres storage requires a database name")
		}
	default:
		return fmt.Errorf("unknown storage type: %s", config.Storage.Type)
	}

	// Validate source configurations
	for i, source := range config.Sources {
		if source.Type == "" {
			return fmt.Errorf("source #%d is missing a type", i+1)
		}

		switch source.Type {
		case "file":
			if source.Path == "" {
				return fmt.Errorf("file source requires a path")
			}
		case "syslog":
			if source.Port == 0 {
				return fmt.Errorf("syslog source requires a port")
			}
		case "api":
			if source.Host == "" {
				return fmt.Errorf("api source requires a host")
			}
		}

		if source.Interval <= 0 {
			return fmt.Errorf("source #%d has a non-positive interval", i+1)
		}
	}

	return nil
}

// SaveConfig writes the configuration to a file
func SaveConfig(config *Config, path string) error {
	// Convert to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %v", err)
	}

	// Write to file
	err = ioutil.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write configuration: %v", err)
	}

	fmt.Printf("Saved configuration to %s\n", path)
	return nil
}

// CreateDefaultConfig generates a default configuration file
func CreateDefaultConfig(path string) error {
	// Create a default configuration
	config := &Config{}

	// General section
	config.General.Name = "Cryon SIEM"
	config.General.Description = "Security Information and Event Management System"
	config.General.Version = "0.1.0"

	// Logging section
	config.Logging.Level = "info"
	config.Logging.File = "cryon.log"
	config.Logging.Verbose = false

	// Storage section
	config.Storage.Type = "memory"

	// Add some default sources
	config.Sources = []collector.SourceConfig{
		{
			Type:     "file",
			Path:     "/var/log/auth.log",
			Interval: 10,
		},
		{
			Type: "syslog",
			Host: "0.0.0.0",
			Port: 10514,
		},
	}

	// Add some default rules
	config.Rules = []analyzer.RuleConfig{
		{
			ID:          "rule-001",
			Name:        "Failed SSH Authentication",
			Description: "Detects failed SSH authentication attempts",
			Severity:    "MEDIUM",
			Type:        "regex",
			Pattern:     "Failed password for .* from .* port \\d+ ssh2",
			Enabled:     true,
		},
		{
			ID:          "rule-002",
			Name:        "Brute Force Attack",
			Description: "Detects potential brute force attacks",
			Severity:    "HIGH",
			Type:        "threshold",
			Pattern:     "Failed password",
			Threshold:   5,
			Timeframe:   60,
			Enabled:     true,
		},
	}

	// API section
	config.API.Enabled = false
	config.API.Port = 8080
	config.API.TLS = false

	// Authentication section
	config.Authentication.Enabled = false
	config.Authentication.Method = "local"

	// Save the configuration
	return SaveConfig(config, path)
}
