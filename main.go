package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/awion/cryon-siem/config"
	"github.com/awion/cryon-siem/public/analyzer"
	"github.com/awion/cryon-siem/public/collector"
	"github.com/awion/cryon-siem/public/storage"
	"github.com/awion/cryon-siem/ui"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	version := flag.Bool("version", false, "Display version information")
	flag.Parse()

	// Display version and exit if requested
	if *version {
		fmt.Println("Cryon SIEM v0.1.0")
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Set up verbose logging if enabled
	if *verbose {
		cfg.Logging.Verbose = true
	}

	// Initialize storage
	store, err := storage.NewStorage(cfg.Storage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing storage: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	// Initialize analyzer
	analyzerEngine := analyzer.NewAnalyzer(cfg.Rules, store)

	// Initialize collector
	collectorEngine := collector.NewCollector(cfg.Sources, store, analyzerEngine)

	// Initialize UI
	cliUI := ui.NewCLI(store, analyzerEngine)

	// Start components
	analyzerEngine.Start()
	collectorEngine.Start()
	cliUI.Start()

	// Set up graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal
	sig := <-sigChan
	fmt.Printf("Received signal %v, shutting down...\n", sig)

	// Stop components
	cliUI.Stop()
	collectorEngine.Stop()
	analyzerEngine.Stop()

	fmt.Println("Cryon SIEM terminated")
}
