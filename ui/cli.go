package ui

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awion/cryon-siem/model"
	"github.com/awion/cryon-siem/public/analyzer"
	"github.com/awion/cryon-siem/public/storage"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// Color definitions using fatih/color package for better cross-platform support
var (
	colorRed       = color.New(color.FgRed).SprintFunc()
	colorYellow    = color.New(color.FgYellow).SprintFunc()
	colorBlue      = color.New(color.FgBlue).SprintFunc()
	colorMagenta   = color.New(color.FgMagenta).SprintFunc()
	colorCyan      = color.New(color.FgCyan).SprintFunc()
	colorWhite     = color.New(color.FgWhite).SprintFunc()
	colorBold      = color.New(color.Bold).SprintFunc()
	colorHighlight = color.New(color.BgBlue, color.FgWhite).SprintFunc()
)

// getSeverityColorFunc returns the appropriate color function for a severity level
func (c *CLI) getSeverityColorFunc(severity model.Severity) func(a ...interface{}) string {
	switch severity {
	case model.SeverityCritical:
		return colorRed
	case model.SeverityHigh:
		return colorMagenta
	case model.SeverityMedium:
		return colorYellow
	case model.SeverityLow:
		return colorBlue
	default:
		return colorWhite
	}
}

// clearScreen clears the terminal screen
func (c *CLI) clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

// showBanner displays the application banner
func (c *CLI) showBanner() {
	fmt.Println(colorCyan(`
   ______                          _____ ________  ___
  / ____/______  ______  ____     / ___//  _/ __ \/   |
 / /   / ___/ / / / __ \/ __ \    \__ \ / // / / / /| |
/ /___/ /  / /_/ / /_/ / / / /   ___/ // // /_/ / ___ |
\____/_/   \__, /\____/_/ /_/   /____/___/\____/_/  |_|
          /____/                                        
`))
}

// showInitialAlerts displays recent alerts on startup
func (c *CLI) showInitialAlerts() {
	alerts := c.storage.GetAlerts(5)
	if len(alerts) > 0 {
		fmt.Println("\nRecent Alerts:")
		c.displayAlertTable(alerts)
	}
}

// displayAlertTable shows alerts in a formatted table
func (c *CLI) displayAlertTable(alerts []model.Alert) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Time", "Severity", "Rule", "Description"})

	for _, alert := range alerts {
		table.Append([]string{
			alert.ID,
			alert.Timestamp.Format("15:04:05"),
			string(alert.Severity),
			alert.RuleName,
			alert.Description,
		})
	}
	table.Render()
}

// showHelp displays available commands
func (c *CLI) showHelp() {
	fmt.Println("\nAvailable Commands:")
	fmt.Println("═════════════════════")
	// ... Add help text for commands
}

// showStatus displays system status
func (c *CLI) showStatus() {
	fmt.Println("\nSystem Status:")
	fmt.Println("══════════════")
	// ... Add status display implementation
}

// showConfigHelp displays configuration help
func (c *CLI) showConfigHelp() {
	fmt.Println("\nConfiguration Commands:")
	fmt.Println("  config list           - Show current configuration")
	fmt.Println("  config set <k> <v>    - Set configuration value")
	fmt.Println("  config save           - Save configuration")
	fmt.Println("  config reset          - Reset to defaults")
}

// CLI represents the command-line interface for the SIEM
type CLI struct {
	storage    *storage.Storage
	analyzer   *analyzer.Analyzer
	stopChan   chan struct{}
	wg         sync.WaitGroup
	startTime  time.Time
	lastCmd    string
	cmdHistory []string
	config     *Config
}

// Config holds the CLI configuration settings
type Config struct {
	RefreshInterval   int
	AlertBatchSize    int
	MaxDisplayLines   int
	ShowTimestamps    bool
	CompactMode       bool
	AutoRefresh       bool
	DefaultEventLimit int
	DefaultAlertLimit int
	ColorEnabled      bool
	LogLevel          string
	NotificationSound bool
	TerminalWidth     int
	TerminalHeight    int
}

// NewCLI creates a new CLI interface with default configuration
func NewCLI(storage *storage.Storage, analyzer *analyzer.Analyzer) *CLI {
	// Default configuration
	config := &Config{
		RefreshInterval:   5,
		AlertBatchSize:    5,
		MaxDisplayLines:   20,
		ShowTimestamps:    true,
		CompactMode:       false,
		AutoRefresh:       true,
		DefaultEventLimit: 10,
		DefaultAlertLimit: 10,
		ColorEnabled:      true,
		LogLevel:          "info",
		NotificationSound: false,
		TerminalWidth:     80,
		TerminalHeight:    24,
	}

	return &CLI{
		storage:    storage,
		analyzer:   analyzer,
		stopChan:   make(chan struct{}),
		startTime:  time.Now(),
		cmdHistory: make([]string, 0, 50),
		config:     config,
	}
}

// Start initializes and starts the CLI interface
func (c *CLI) Start() {
	// Set up terminal dimensions
	c.updateTerminalDimensions()

	// Handle SIGWINCH to update terminal dimensions on resize
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGWINCH)
	go func() {
		for range sigChan {
			c.updateTerminalDimensions()
		}
	}()

	// Handle SIGINT gracefully
	sigIntChan := make(chan os.Signal, 1)
	signal.Notify(sigIntChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigIntChan
		fmt.Println("\nReceived interrupt, shutting down...")
		c.Stop()
		os.Exit(0)
	}()

	fmt.Println("Starting Cryon SIEM CLI...")

	// Display recent alerts first
	c.showInitialAlerts()

	// Ask user to continue
	fmt.Print("\nPress Enter to continue to CLI...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Clear screen and show menu
	c.clearScreen()
	fmt.Println("Welcome to Cryon SIEM Command Line Interface")
	fmt.Println("--------------------------------------------")
	c.showMenu()

	// Start alert display
	c.wg.Add(1)
	go c.displayAlerts()

	// Start command processor
	c.wg.Add(1)
	go c.processCommands()

	// Start background refresh for status display if enabled
	if c.config.AutoRefresh {
		c.wg.Add(1)
		go c.backgroundRefresh()
	}
}

// Stop halts the CLI interface
func (c *CLI) Stop() {
	fmt.Println("Stopping CLI...")

	close(c.stopChan)
	c.wg.Wait()

	fmt.Println("CLI stopped")
}

// updateTerminalDimensions gets current terminal dimensions
func (c *CLI) updateTerminalDimensions() {
	if w, h, err := getTerminalDimensions(); err == nil {
		c.config.TerminalWidth = w
		c.config.TerminalHeight = h
	}
}

// getTerminalDimensions returns width and height of terminal
func getTerminalDimensions() (int, int, error) {
	// Default fallback values
	width, height := 80, 24

	// This is a placeholder function - implement proper terminal size detection
	// based on your platform using appropriate libraries

	return width, height, nil
}

// backgroundRefresh periodically refreshes status information
func (c *CLI) backgroundRefresh() {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Duration(c.config.RefreshInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Only refresh if in status view and auto-refresh is enabled
			if c.lastCmd == "status" && c.config.AutoRefresh {
				c.showStatus()
			}
		case <-c.stopChan:
			return
		}
	}
}

// displayAlerts shows new alerts in real-time with improved batching
func (c *CLI) displayAlerts() {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Duration(c.config.RefreshInterval) * time.Second)
	defer ticker.Stop()

	var lastAlertCount int
	var lastDisplayTime time.Time
	var batchAlerts []model.Alert
	minInterval := 10 * time.Second // Minimum time between alert displays

	for {
		select {
		case <-ticker.C:
			alerts := c.storage.GetAlerts(100)

			if len(alerts) > lastAlertCount {
				// Collect new alerts
				for i := lastAlertCount; i < len(alerts); i++ {
					batchAlerts = append(batchAlerts, alerts[i])
				}

				// Display alerts in batches with timing control
				if (time.Since(lastDisplayTime) > minInterval && len(batchAlerts) > 0) ||
					len(batchAlerts) >= c.config.AlertBatchSize {

					// Don't interrupt if user is typing a command - check if last character is '>'
					lastChar := getLastTerminalChar()
					if lastChar != '>' {
						c.displayAlertBatch(batchAlerts)
						batchAlerts = nil // Clear the batch
						lastDisplayTime = time.Now()
					}
				}

				lastAlertCount = len(alerts)
			}

		case <-c.stopChan:
			return
		}
	}
}

// getLastTerminalChar is a placeholder function to check terminal state
func getLastTerminalChar() byte {
	// This is a placeholder - in a real implementation, you would
	// check the actual last character on the terminal screen
	// This is complex and platform-dependent
	return ' '
}

// displayAlertBatch shows a batch of alerts with better formatting
func (c *CLI) displayAlertBatch(alerts []model.Alert) {
	if len(alerts) == 0 {
		return
	}

	// Deduplicate alerts by combining similar ones
	alertGroups := make(map[string][]model.Alert)
	for _, alert := range alerts {
		key := fmt.Sprintf("%s-%s", alert.Severity, alert.RuleID)
		alertGroups[key] = append(alertGroups[key], alert)
	}

	fmt.Printf("\n%s\n", colorBold(colorYellow("╔═ New Alerts ═════════════════════════════════════")))

	// Use range variable names that reflect their purpose
	for _, group := range alertGroups {
		alert := group[0] // Use first alert as representative
		sevColor := c.getSeverityColorFunc(alert.Severity)
		count := len(group)

		countStr := ""
		if count > 1 {
			countStr = fmt.Sprintf(" (%d occurrences)", count)
		}

		fmt.Printf("║ %s [%s] %s%s\n",
			sevColor(fmt.Sprintf("%-8s", alert.Severity)),
			time.Now().Format("15:04:05"),
			alert.RuleName,
			countStr)
	}

	fmt.Printf("%s\n", colorYellow("╚═════════════════════════════════════════════════════"))

	// Play sound notification if enabled
	if c.config.NotificationSound {
		playAlertSound()
	}
}

// processCommands handles user input and commands with improved history
func (c *CLI) processCommands() {
	defer c.wg.Done()

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("\nCryon SIEM Command Line Interface")
	fmt.Println("Type 'help' for available commands")

	for {
		select {
		case <-c.stopChan:
			return
		default:
			fmt.Print("\n> ")
			if !scanner.Scan() {
				return
			}

			command := scanner.Text()
			if command != "" {
				// Add to command history, avoiding duplicates
				if len(c.cmdHistory) == 0 || c.cmdHistory[len(c.cmdHistory)-1] != command {
					if len(c.cmdHistory) >= 50 {
						c.cmdHistory = c.cmdHistory[1:]
					}
					c.cmdHistory = append(c.cmdHistory, command)
				}

				c.lastCmd = command
				c.executeCommand(command)
			}
		}
	}
}

// executeCommand processes a user command with enhanced parsing
func (c *CLI) executeCommand(command string) {
	// Split by quotes to preserve quoted sections
	parts := c.parseCommandWithQuotes(command)
	if len(parts) == 0 {
		return
	}

	// Convert command to lowercase for case-insensitive matching
	// but preserve case for arguments
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "h", "?":
		c.showHelp()
	case "menu", "m":
		c.showMenu()
	case "status", "1", "s":
		c.showStatus()
	case "events", "2", "e":
		c.handleEventCommand(args)
	case "alerts", "3", "a":
		c.handleAlertCommand(args)
	case "rules", "4", "r":
		c.handleRuleCommand(args)
	case "config", "5", "c":
		c.handleConfigCommand(args)
	case "search":
		c.handleSearchCommand(args)
	case "clear", "cls":
		c.clearScreen()
		c.showMenu()
	case "history":
		c.showCommandHistory()
	case "refresh":
		// Refresh current view based on last command
		c.refreshCurrentView()
	case "exit", "quit", "q":
		fmt.Println("Use Ctrl+C to exit Cryon SIEM")
	default:
		fmt.Printf("%s: Unknown command: %s\n", colorRed("Error"), parts[0])
		fmt.Println("Type 'help' to see available commands")
	}
}

// parseCommandWithQuotes splits command respecting quoted strings
func (c *CLI) parseCommandWithQuotes(command string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for _, r := range command {
		switch {
		case r == '"' || r == '\'':
			inQuotes = !inQuotes
		case r == ' ' && !inQuotes:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// refreshCurrentView refreshes the current view based on last command
func (c *CLI) refreshCurrentView() {
	cmdParts := strings.Fields(c.lastCmd)
	if len(cmdParts) == 0 {
		c.showMenu()
		return
	}

	switch cmdParts[0] {
	case "status", "1":
		c.showStatus()
	case "events", "2":
		c.handleEventCommand(cmdParts[1:])
	case "alerts", "3":
		c.handleAlertCommand(cmdParts[1:])
	case "rules", "4":
		c.handleRuleCommand(cmdParts[1:])
	default:
		c.showMenu()
	}
}

// handleEventCommand processes event-related commands
func (c *CLI) handleEventCommand(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "show":
			if len(args) > 1 {
				c.showEventDetail(args[1])
			} else {
				fmt.Println("Usage: events show <event_id>")
			}
		case "filter":
			if len(args) > 1 {
				c.showFilteredEvents(args[1:])
			} else {
				fmt.Println("Usage: events filter <field> <value>")
			}
		case "export":
			if len(args) > 1 {
				c.exportEvents(args[1])
			} else {
				fmt.Println("Usage: events export <filename>")
			}
		default:
			// Try to parse as a number (limit)
			if limit, err := strconv.Atoi(args[0]); err == nil {
				c.showEvents(limit)
			} else {
				fmt.Printf("Unknown events subcommand: %s\n", args[0])
				c.showEventsHelp()
			}
		}
	} else {
		c.showEvents(c.config.DefaultEventLimit)
	}
}

// showEventsHelp displays help for event commands
func (c *CLI) showEventsHelp() {
	fmt.Println("\nEvent Commands:")
	fmt.Println("  events                  - Show recent events (default limit)")
	fmt.Println("  events <n>              - Show last n events")
	fmt.Println("  events show <id>        - Show detailed event information")
	fmt.Println("  events filter <f> <v>   - Filter events by field and value")
	fmt.Println("  events export <file>    - Export events to a file")
}

// handleAlertCommand processes alert-related commands
func (c *CLI) handleAlertCommand(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "show":
			if len(args) > 1 {
				c.showAlertDetail(args[1])
			} else {
				fmt.Println("Usage: alerts show <alert_id>")
			}
		case "ack", "acknowledge":
			if len(args) > 1 {
				c.acknowledgeAlert(args[1])
			} else {
				fmt.Println("Usage: alerts ack <alert_id>")
			}
		case "filter":
			if len(args) > 1 {
				c.showFilteredAlerts(args[1:])
			} else {
				fmt.Println("Usage: alerts filter <field> <value>")
			}
		case "severity":
			if len(args) > 1 {
				c.showAlertsBySeverity(model.Severity(args[1]))
			} else {
				fmt.Println("Usage: alerts severity <level>")
			}
		case "export":
			if len(args) > 1 {
				c.exportAlerts(args[1])
			} else {
				fmt.Println("Usage: alerts export <filename>")
			}
		default:
			// Try to parse as a number (limit)
			if limit, err := strconv.Atoi(args[0]); err == nil {
				c.showAlerts(limit)
			} else {
				fmt.Printf("Unknown alerts subcommand: %s\n", args[0])
				c.showAlertsHelp()
			}
		}
	} else {
		c.showAlerts(c.config.DefaultAlertLimit)
	}
}

// showAlertsHelp displays help for alert commands
func (c *CLI) showAlertsHelp() {
	fmt.Println("\nAlert Commands:")
	fmt.Println("  alerts                  - Show recent alerts (default limit)")
	fmt.Println("  alerts <n>              - Show last n alerts")
	fmt.Println("  alerts show <id>        - Show detailed alert information")
	fmt.Println("  alerts ack <id>         - Acknowledge an alert")
	fmt.Println("  alerts filter <f> <v>   - Filter alerts by field and value")
	fmt.Println("  alerts severity <level> - Show alerts of specific severity")
	fmt.Println("  alerts export <file>    - Export alerts to a file")
}

// handleRuleCommand processes rule-related commands
func (c *CLI) handleRuleCommand(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "show":
			if len(args) > 1 {
				c.showRuleDetail(args[1])
			} else {
				fmt.Println("Usage: rules show <rule_id>")
			}
		case "enable":
			if len(args) > 1 {
				c.enableRule(args[1])
			} else {
				fmt.Println("Usage: rules enable <rule_id>")
			}
		case "disable":
			if len(args) > 1 {
				c.disableRule(args[1])
			} else {
				fmt.Println("Usage: rules disable <rule_id>")
			}
		case "test":
			if len(args) > 1 {
				c.testRule(args[1])
			} else {
				fmt.Println("Usage: rules test <rule_id>")
			}
		case "add":
			c.addRule()
		case "edit":
			if len(args) > 1 {
				c.editRule(args[1])
			} else {
				fmt.Println("Usage: rules edit <rule_id>")
			}
		default:
			fmt.Printf("Unknown rules subcommand: %s\n", args[0])
			c.showRulesHelp()
		}
	} else {
		c.showRules()
	}
}

// showRulesHelp displays help for rule commands
func (c *CLI) showRulesHelp() {
	fmt.Println("\nRule Commands:")
	fmt.Println("  rules                 - List all detection rules")
	fmt.Println("  rules show <id>       - Show detailed rule information")
	fmt.Println("  rules enable <id>     - Enable a rule")
	fmt.Println("  rules disable <id>    - Disable a rule")
	fmt.Println("  rules test <id>       - Test a rule against sample data")
	fmt.Println("  rules add             - Add a new rule")
	fmt.Println("  rules edit <id>       - Edit an existing rule")
}

// handleSearchCommand processes search queries
func (c *CLI) handleSearchCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: search <query> [options]")
		return
	}

	query := args[0]
	options := args[1:]

	fmt.Printf("\nSearching for: %s\n", colorHighlight(query))
	if len(options) > 0 {
		fmt.Printf("With options: %s\n", strings.Join(options, " "))
	}

	// Placeholder for actual search implementation
	fmt.Println("Search feature is not yet implemented")
}

// handleConfigCommand processes configuration-related commands
func (c *CLI) handleConfigCommand(args []string) {
	if len(args) == 0 {
		c.showConfigHelp()
		return
	}

	switch args[0] {
	case "list":
		c.showConfig()
	case "set":
		if len(args) != 3 {
			fmt.Println("Usage: config set <key> <value>")
			return
		}
		c.setConfig(args[1], args[2])
	case "save":
		c.saveConfig()
	case "reset":
		c.resetConfig()
	case "theme":
		if len(args) > 1 {
			c.setTheme(args[1])
		} else {
			fmt.Println("Usage: config theme <theme_name>")
		}
	default:
		c.showConfigHelp()
	}
}

// showCommandHistory displays command history
func (c *CLI) showCommandHistory() {
	if len(c.cmdHistory) == 0 {
		fmt.Println("No command history yet")
		return
	}

	fmt.Println("\nCommand History:")
	fmt.Println("═════════════════")

	for i, cmd := range c.cmdHistory {
		fmt.Printf(" %2d: %s\n", i+1, cmd)
	}
}

// acknowledgeAlert marks an alert as acknowledged
func (c *CLI) acknowledgeAlert(id string) {
	// Placeholder for actual implementation
	fmt.Printf("Alert %s acknowledged\n", id)
}

// showFilteredEvents displays events filtered by criteria
func (c *CLI) showFilteredEvents(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: events filter <field> <value>")
		return
	}

	field := args[0]
	value := args[1]

	fmt.Printf("\nShowing events where %s = %s\n", field, value)

	// Placeholder for actual implementation
	c.showEvents(10)
}

// showFilteredAlerts displays alerts filtered by criteria
func (c *CLI) showFilteredAlerts(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: alerts filter <field> <value>")
		return
	}

	field := args[0]
	value := args[1]

	fmt.Printf("\nShowing alerts where %s = %s\n", field, value)

	// Placeholder for actual implementation
	c.showAlerts(10)
}

// showAlertsBySeverity displays alerts of a specific severity
func (c *CLI) showAlertsBySeverity(severity model.Severity) {
	fmt.Printf("\nShowing alerts with severity: %s\n", string(severity))

	// Get alerts and filter by severity
	allAlerts := c.storage.GetAlerts(100)
	var filtered []model.Alert

	for _, alert := range allAlerts {
		if alert.Severity == severity {
			filtered = append(filtered, alert)
		}
	}

	if len(filtered) == 0 {
		fmt.Printf("No alerts found with severity: %s\n", string(severity))
		return
	}

	c.displayAlertTable(filtered)
}

// exportEvents exports events to a file
func (c *CLI) exportEvents(filename string) {
	// Placeholder for actual implementation
	fmt.Printf("Exporting events to %s...\n", filename)
	fmt.Println("Export feature is not yet implemented")
}

// exportAlerts exports alerts to a file
func (c *CLI) exportAlerts(filename string) {
	// Placeholder for actual implementation
	fmt.Printf("Exporting alerts to %s...\n", filename)
	fmt.Println("Export feature is not yet implemented")
}

// enableRule enables a detection rule
func (c *CLI) enableRule(id string) {
	// Find the rule
	for _, rule := range c.analyzer.GetRules() {
		if rule.ID == id {
			// Toggle rule status
			rule.Enabled = true
			fmt.Printf("Rule '%s' enabled\n", id)
			return
		}
	}

	fmt.Printf("Rule with ID '%s' not found\n", id)
}

// disableRule disables a detection rule
func (c *CLI) disableRule(id string) {
	// Find the rule
	for _, rule := range c.analyzer.GetRules() {
		if rule.ID == id {
			// Toggle rule status
			rule.Enabled = false
			fmt.Printf("Rule '%s' disabled\n", id)
			return
		}
	}

	fmt.Printf("Rule with ID '%s' not found\n", id)
}

// testRule tests a rule against sample data
func (c *CLI) testRule(id string) {
	// Placeholder for actual implementation
	fmt.Printf("Testing rule '%s'...\n", id)
	fmt.Println("Test feature is not yet implemented")
}

// addRule adds a new detection rule
func (c *CLI) addRule() {
	// Placeholder for actual implementation
	fmt.Println("Adding new rule...")
	fmt.Println("This feature is not yet implemented")
}

// editRule edits an existing detection rule
func (c *CLI) editRule(id string) {
	// Placeholder for actual implementation
	fmt.Printf("Editing rule '%s'...\n", id)
	fmt.Println("This feature is not yet implemented")
}

// showRuleDetail displays detailed information about a specific rule
func (c *CLI) showRuleDetail(id string) {
	var foundRule *model.Rule
	for _, ruleConfig := range c.analyzer.GetRules() {
		if ruleConfig.ID == id {
			foundRule = convertRuleConfig(&ruleConfig)
			break
		}
	}

	if foundRule == nil {
		fmt.Printf("Rule with ID '%s' not found\n", id)
		return
	}

	// Display rule details
	status := "DISABLED"
	if foundRule.Enabled {
		status = "ENABLED"
	}

	fmt.Println("\nRule Details:")
	fmt.Println("═════════════")
	fmt.Printf("ID:          %s\n", foundRule.ID)
	fmt.Printf("Name:        %s\n", foundRule.Name)
	fmt.Printf("Description: %s\n", foundRule.Description)
	fmt.Printf("Severity:    %s\n", string(foundRule.Severity))
	fmt.Printf("Status:      %s\n", status)

	// Display rule pattern/matcher details
	fmt.Println("\nDetection Criteria:")
	fmt.Printf("Type:        %s\n", foundRule.Type)
	fmt.Printf("Pattern:     %s\n", foundRule.Pattern)

	// Display related alerts count
	alertCount := 0
	for _, alert := range c.storage.GetAlerts(1000) {
		if alert.RuleID == foundRule.ID {
			alertCount++
		}
	}
	fmt.Printf("\nTriggered:    %d times\n", alertCount)
}

// setTheme changes the color theme
func (c *CLI) setTheme(themeName string) {
	// Placeholder for theme implementation
	fmt.Printf("Switching to theme: %s\n", themeName)
	fmt.Println("Theme feature is not yet implemented")
}

// resetConfig resets configuration to defaults
func (c *CLI) resetConfig() {
	c.config = &Config{
		RefreshInterval:   5,
		AlertBatchSize:    5,
		MaxDisplayLines:   20,
		ShowTimestamps:    true,
		CompactMode:       false,
		AutoRefresh:       true,
		DefaultEventLimit: 10,
		DefaultAlertLimit: 10,
		ColorEnabled:      true,
		LogLevel:          "info",
		NotificationSound: false,
	}

	fmt.Println("Configuration reset to defaults")
}

// showMenu displays the main menu with improved visual design
func (c *CLI) showMenu() {
	c.clearScreen()
	c.showBanner()

	fmt.Printf("\n%s\n", colorBold("Main Menu:"))

	// Use table for better alignment
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetColumnSeparator("│")
	table.SetHeaderLine(false)
	table.SetNoWhiteSpace(true)

	// Add menu options
	table.Append([]string{colorCyan("1") + " or " + colorCyan("s"), "System Status", "View system health and alert statistics"})
	table.Append([]string{colorCyan("2") + " or " + colorCyan("e"), "Events", "Monitor security events"})
	table.Append([]string{colorCyan("3") + " or " + colorCyan("a"), "Alerts", "View and manage security alerts"})
	table.Append([]string{colorCyan("4") + " or " + colorCyan("r"), "Rules", "Configure detection rules"})
	table.Append([]string{colorCyan("5") + " or " + colorCyan("c"), "Settings", "System configuration"})
	table.Append([]string{colorCyan("search"), "Search", "Search across events and alerts"})
	table.Append([]string{colorCyan("clear"), "Clear Screen", "Clear terminal display"})
	table.Append([]string{colorCyan("help") + " or " + colorCyan("?"), "Help", "Display help information"})
	table.Append([]string{colorCyan("quit") + " or " + colorCyan("q"), "Quit", "Exit application"})

	table.Render()

	// Show system overview
	c.showQuickStatus()
}

// showQuickStatus shows a condensed status overview for the main menu
func (c *CLI) showQuickStatus() {
	events := c.storage.GetEvents(1000)
	alerts := c.storage.GetAlerts(1000)

	fmt.Printf("\n%s\n", colorBold("Quick Status:"))
	fmt.Printf("═════════════════════════════════════\n")
	fmt.Printf("Uptime:     %s\n", c.getUptimeString())
	fmt.Printf("Events:     %d (last 24h)\n", len(events))
	fmt.Printf("Alerts:     %d (%d critical)\n", len(alerts), c.countCriticalAlerts(alerts))
	fmt.Printf("Rules:      %d active\n", c.countActiveRules())
	fmt.Printf("CPU Usage:  %s\n", c.getSystemUsage())
	fmt.Printf("Memory:     %s\n", c.getMemoryUsage())
}

// getUptimeString formats the system uptime
func (c *CLI) getUptimeString() string {
	uptime := time.Since(c.startTime)
	days := int(uptime.Hours() / 24)
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// countCriticalAlerts returns the number of critical severity alerts
func (c *CLI) countCriticalAlerts(alerts []model.Alert) int {
	count := 0
	for _, alert := range alerts {
		if alert.Severity == model.SeverityCritical {
			count++
		}
	}
	return count
}

// countActiveRules returns the number of enabled detection rules
func (c *CLI) countActiveRules() int {
	count := 0
	for _, rule := range c.analyzer.GetRules() {
		if rule.Enabled {
			count++
		}
	}
	return count
}

// getSystemUsage returns formatted CPU usage
func (c *CLI) getSystemUsage() string {
	var cpuLoad float64
	if runtime.GOOS == "linux" {
		// Try to read from /proc/loadavg on Linux
		if data, err := os.ReadFile("/proc/loadavg"); err == nil {
			fmt.Sscanf(string(data), "%f", &cpuLoad)
		}
	}

	if cpuLoad > 0 {
		return fmt.Sprintf("%.1f%%", cpuLoad*100)
	}
	return "N/A"
}

// getMemoryUsage returns formatted memory usage
func (c *CLI) getMemoryUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("%.1f MB", float64(m.Alloc)/1024/1024)
}

// showEvents displays a list of recent events with optional limit
func (c *CLI) showEvents(limit int) {
	events := c.storage.GetEvents(limit)
	if len(events) == 0 {
		fmt.Println("No events found")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Time", "Source", "Type", "Description"})

	for _, event := range events {
		table.Append([]string{
			event.Timestamp.Format("2006-01-02 15:04:05"),
			event.Source,
			event.Type,
			event.Description,
		})
	}
	table.Render()
}

// Fix showEventDetail
func (c *CLI) showEventDetail(id string) {
	event, ok := c.storage.GetEvent(id)
	if !ok {
		fmt.Printf("Event with ID '%s' not found\n", id)
		return
	}

	fmt.Printf("\nEvent Details [%s]:\n", id)
	fmt.Println("═════════════════════")
	fmt.Printf("Time:        %s\n", event.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Source:      %s\n", event.Source)
	fmt.Printf("Type:        %s\n", event.Type)
	fmt.Printf("Description: %s\n", event.Description)

	if len(event.Data) > 0 {
		fmt.Println("\nAdditional Data:")
		for k, v := range event.Data {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
}

// showAlerts displays a list of alerts with optional limit
func (c *CLI) showAlerts(limit int) {
	alerts := c.storage.GetAlerts(limit)
	if len(alerts) == 0 {
		fmt.Println("No alerts found")
		return
	}
	c.displayAlertTable(alerts)
}

// Fix showAlertDetail
func (c *CLI) showAlertDetail(id string) {
	alert, ok := c.storage.GetAlert(id)
	if !ok {
		fmt.Printf("Alert with ID '%s' not found\n", id)
		return
	}

	fmt.Printf("\nAlert Details [%s]:\n", id)
	fmt.Println("═════════════════════")
	fmt.Printf("Time:        %s\n", alert.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Rule:        %s (%s)\n", alert.RuleName, alert.RuleID)
	fmt.Printf("Severity:    %s\n", alert.Severity)
	fmt.Printf("Description: %s\n", alert.Description)

	if len(alert.Data) > 0 {
		fmt.Println("\nAlert Data:")
		for k, v := range alert.Data {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
}

// showRules displays all detection rules
func (c *CLI) showRules() {
	rules := c.analyzer.GetRules()
	if len(rules) == 0 {
		fmt.Println("No rules defined")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Name", "Severity", "Status"})

	for _, rule := range rules {
		status := "Disabled"
		if rule.Enabled {
			status = "Enabled"
		}

		table.Append([]string{
			rule.ID,
			rule.Name,
			string(rule.Severity),
			status,
		})
	}
	table.Render()
}

// showConfig displays current configuration
func (c *CLI) showConfig() {
	fmt.Println("\nCurrent Configuration:")
	fmt.Println("═════════════════════")
	fmt.Printf("Refresh Interval:    %d seconds\n", c.config.RefreshInterval)
	fmt.Printf("Alert Batch Size:    %d\n", c.config.AlertBatchSize)
	fmt.Printf("Max Display Lines:   %d\n", c.config.MaxDisplayLines)
	fmt.Printf("Show Timestamps:     %v\n", c.config.ShowTimestamps)
	fmt.Printf("Compact Mode:        %v\n", c.config.CompactMode)
	fmt.Printf("Auto Refresh:        %v\n", c.config.AutoRefresh)
	fmt.Printf("Default Event Limit: %d\n", c.config.DefaultEventLimit)
	fmt.Printf("Default Alert Limit: %d\n", c.config.DefaultAlertLimit)
	fmt.Printf("Color Enabled:       %v\n", c.config.ColorEnabled)
	fmt.Printf("Log Level:          %s\n", c.config.LogLevel)
	fmt.Printf("Notification Sound:  %v\n", c.config.NotificationSound)
}

// setConfig updates a configuration value
func (c *CLI) setConfig(key, value string) {
	switch strings.ToLower(key) {
	case "refresh":
		if i, err := strconv.Atoi(value); err == nil {
			c.config.RefreshInterval = i
		}
	case "batchsize":
		if i, err := strconv.Atoi(value); err == nil {
			c.config.AlertBatchSize = i
		}
	case "maxlines":
		if i, err := strconv.Atoi(value); err == nil {
			c.config.MaxDisplayLines = i
		}
	case "timestamps":
		c.config.ShowTimestamps = value == "true"
	case "compact":
		c.config.CompactMode = value == "true"
	case "autorefresh":
		c.config.AutoRefresh = value == "true"
	case "sound":
		c.config.NotificationSound = value == "true"
	case "loglevel":
		c.config.LogLevel = value
	default:
		fmt.Printf("Unknown configuration key: %s\n", key)
		return
	}
	fmt.Printf("Configuration updated: %s = %s\n", key, value)
}

// saveConfig saves the current configuration
func (c *CLI) saveConfig() {
	// Placeholder - implement actual config saving
	fmt.Println("Configuration saved")
}

// playAlertSound plays a sound notification for alerts
func playAlertSound() {
	// Placeholder for actual sound playing implementation
	fmt.Println("Playing alert sound...")
}

// Add rule type conversion helper
func convertRuleConfig(rc *analyzer.RuleConfig) *model.Rule {
	return &model.Rule{
		ID:          rc.ID,
		Name:        rc.Name,
		Description: rc.Description,
		Severity:    model.ParseSeverity(rc.Severity),
		Type:        rc.Type,
		Pattern:     rc.Pattern,
		Enabled:     rc.Enabled,
	}
}
