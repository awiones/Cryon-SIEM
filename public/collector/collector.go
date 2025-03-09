package collector

import (
	"fmt"
	"sync"
	"time"

	"github.com/awion/cryon-siem/model"
	"github.com/awion/cryon-siem/public/analyzer"
	"github.com/awion/cryon-siem/public/storage"
)

// SourceConfig represents configuration for a data source
type SourceConfig struct {
	Type       string            `yaml:"type"`
	Path       string            `yaml:"path"`
	Host       string            `yaml:"host"`
	Port       int               `yaml:"port"`
	Interval   int               `yaml:"interval"`
	Parameters map[string]string `yaml:"parameters"`
}

// Collector manages the collection of security events from various sources
type Collector struct {
	sources    []SourceConfig
	storage    *storage.Storage
	analyzer   *analyzer.Analyzer
	collectors []EventCollector
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// EventCollector interface for different collector types
type EventCollector interface {
	Start()
	Stop()
}

// NewCollector creates a new collector engine
func NewCollector(sources []SourceConfig, storage *storage.Storage, analyzer *analyzer.Analyzer) *Collector {
	return &Collector{
		sources:  sources,
		storage:  storage,
		analyzer: analyzer,
		stopChan: make(chan struct{}),
	}
}

// Start initializes and starts all configured collectors
func (c *Collector) Start() {
	fmt.Println("Starting Cryon SIEM collectors...")

	for _, source := range c.sources {
		var collector EventCollector

		switch source.Type {
		case "file":
			collector = NewFileCollector(source, c.storage, c.analyzer)
		case "syslog":
			collector = NewSyslogCollector(source, c.storage, c.analyzer)
		case "winlog":
			collector = NewWindowsEventCollector(source, c.storage, c.analyzer)
		case "api":
			collector = NewAPICollector(source, c.storage, c.analyzer)
		default:
			fmt.Printf("Unknown collector type: %s\n", source.Type)
			continue
		}

		c.collectors = append(c.collectors, collector)
		collector.Start()
	}

	// Start the routing of events to analyzer
	c.wg.Add(1)
	go c.processEvents()
}

// Stop halts all collectors
func (c *Collector) Stop() {
	fmt.Println("Stopping collectors...")

	close(c.stopChan)

	for _, collector := range c.collectors {
		collector.Stop()
	}

	c.wg.Wait()
	fmt.Println("All collectors stopped")
}

// processEvents handles the routing of events to the analyzer
func (c *Collector) processEvents() {
	defer c.wg.Done()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			events := c.storage.GetUnprocessedEvents(100)
			for _, event := range events {
				c.analyzer.AnalyzeEvent(event)
				c.storage.MarkEventProcessed(event.ID)
			}
		case <-c.stopChan:
			return
		}
	}
}

// FileCollector implements collection from log files
type FileCollector struct {
	config   SourceConfig
	storage  *storage.Storage
	analyzer *analyzer.Analyzer
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewFileCollector creates a new file-based collector
func NewFileCollector(config SourceConfig, storage *storage.Storage, analyzer *analyzer.Analyzer) *FileCollector {
	return &FileCollector{
		config:   config,
		storage:  storage,
		analyzer: analyzer,
		stopChan: make(chan struct{}),
	}
}

// Start begins collecting events from the configured file source
func (fc *FileCollector) Start() {
	if fc.config.Interval <= 0 {
		panic("non-positive interval for FileCollector")
	}

	fc.wg.Add(1)
	go func() {
		defer fc.wg.Done()

		fmt.Printf("Starting file collector for %s\n", fc.config.Path)

		ticker := time.NewTicker(time.Duration(fc.config.Interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Read file and collect new events
				events := fc.readLogFile()
				for _, event := range events {
					fc.storage.StoreEvent(event)
				}
			case <-fc.stopChan:
				return
			}
		}
	}()
}

// Stop halts the file collector
func (fc *FileCollector) Stop() {
	close(fc.stopChan)
	fc.wg.Wait()
}

// readLogFile reads and parses the configured log file
func (fc *FileCollector) readLogFile() []model.Event {
	// Implementation for reading and parsing log files
	// This is a placeholder - real implementation would parse the file format
	events := []model.Event{}

	// Mock implementation for demonstration
	event := model.Event{
		ID:        "file-event-1",
		Timestamp: time.Now(),
		Source:    fc.config.Path,
		Type:      "file_log",
		RawData:   []byte("Sample log entry"),
		Severity:  model.SeverityInfo,
	}

	events = append(events, event)
	return events
}

// SyslogCollector implements collection from syslog
type SyslogCollector struct {
	config   SourceConfig
	storage  *storage.Storage
	analyzer *analyzer.Analyzer
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewSyslogCollector creates a new syslog-based collector
func NewSyslogCollector(config SourceConfig, storage *storage.Storage, analyzer *analyzer.Analyzer) *SyslogCollector {
	return &SyslogCollector{
		config:   config,
		storage:  storage,
		analyzer: analyzer,
		stopChan: make(chan struct{}),
	}
}

// Start begins collecting events from the configured syslog source
func (sc *SyslogCollector) Start() {
	if sc.config.Interval <= 0 {
		panic("non-positive interval for SyslogCollector")
	}

	sc.wg.Add(1)
	go func() {
		defer sc.wg.Done()

		fmt.Printf("Starting syslog collector on %s:%d\n", sc.config.Host, sc.config.Port)

		// Implementation for reading and parsing syslog
		// This is a placeholder - real implementation would parse the syslog format
		ticker := time.NewTicker(time.Duration(sc.config.Interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Mock implementation for demonstration
				event := model.Event{
					ID:        "syslog-event-1",
					Timestamp: time.Now(),
					Source:    fmt.Sprintf("%s:%d", sc.config.Host, sc.config.Port),
					Type:      "syslog",
					RawData:   []byte("Sample syslog entry"),
					Severity:  model.SeverityInfo,
				}
				sc.storage.StoreEvent(event)
			case <-sc.stopChan:
				return
			}
		}
	}()
}

// Stop halts the syslog collector
func (sc *SyslogCollector) Stop() {
	close(sc.stopChan)
	sc.wg.Wait()
}

// WindowsEventCollector implements collection from Windows Event Log
type WindowsEventCollector struct {
	config   SourceConfig
	storage  *storage.Storage
	analyzer *analyzer.Analyzer
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewWindowsEventCollector creates a new Windows Event Log collector
func NewWindowsEventCollector(config SourceConfig, storage *storage.Storage, analyzer *analyzer.Analyzer) *WindowsEventCollector {
	return &WindowsEventCollector{
		config:   config,
		storage:  storage,
		analyzer: analyzer,
		stopChan: make(chan struct{}),
	}
}

// Start begins collecting events from the configured Windows Event Log source
func (wc *WindowsEventCollector) Start() {
	if wc.config.Interval <= 0 {
		panic("non-positive interval for WindowsEventCollector")
	}

	wc.wg.Add(1)
	go func() {
		defer wc.wg.Done()

		fmt.Printf("Starting Windows Event Log collector for %s\n", wc.config.Path)

		// Implementation for reading and parsing Windows Event Log
		// This is a placeholder - real implementation would parse the event log format
		ticker := time.NewTicker(time.Duration(wc.config.Interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Mock implementation for demonstration
				event := model.Event{
					ID:        "winlog-event-1",
					Timestamp: time.Now(),
					Source:    wc.config.Path,
					Type:      "winlog",
					RawData:   []byte("Sample Windows Event Log entry"),
					Severity:  model.SeverityInfo,
				}
				wc.storage.StoreEvent(event)
			case <-wc.stopChan:
				return
			}
		}
	}()
}

// Stop halts the Windows Event Log collector
func (wc *WindowsEventCollector) Stop() {
	close(wc.stopChan)
	wc.wg.Wait()
}

// APICollector implements collection from an API
type APICollector struct {
	config   SourceConfig
	storage  *storage.Storage
	analyzer *analyzer.Analyzer
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewAPICollector creates a new API-based collector
func NewAPICollector(config SourceConfig, storage *storage.Storage, analyzer *analyzer.Analyzer) *APICollector {
	return &APICollector{
		config:   config,
		storage:  storage,
		analyzer: analyzer,
		stopChan: make(chan struct{}),
	}
}

// Start begins collecting events from the configured API source
func (ac *APICollector) Start() {
	if ac.config.Interval <= 0 {
		panic("non-positive interval for APICollector")
	}

	ac.wg.Add(1)
	go func() {
		defer ac.wg.Done()

		fmt.Printf("Starting API collector for %s\n", ac.config.Host)

		// Implementation for reading and parsing API responses
		// This is a placeholder - real implementation would parse the API response format
		ticker := time.NewTicker(time.Duration(ac.config.Interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Mock implementation for demonstration
				event := model.Event{
					ID:        "api-event-1",
					Timestamp: time.Now(),
					Source:    ac.config.Host,
					Type:      "api",
					RawData:   []byte("Sample API entry"),
					Severity:  model.SeverityInfo,
				}
				ac.storage.StoreEvent(event)
			case <-ac.stopChan:
				return
			}
		}
	}()
}

// Stop halts the API collector
func (ac *APICollector) Stop() {
	close(ac.stopChan)
	ac.wg.Wait()
}
