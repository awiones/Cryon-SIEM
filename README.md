# Cryon SIEM

Cryon SIEM is a lightweight, open-source Security Information and Event Management (SIEM) system written in Go. This project is currently in prototype stage.

## Features

- Real-time security event collection and analysis
- Multiple data source support (files, syslog, Windows Event Log, API)
- Flexible rule-based detection engine
- Correlation analysis capabilities
- In-memory and persistent storage options
- Command-line interface with real-time monitoring

## Requirements

- Go 1.20 or higher
- YAML support for configuration
- Linux/Unix system (Windows support is experimental)

## Quick Start

1. Clone the repository:

```bash
git clone https://github.com/awiones/cryon-siem.git
cd cryon-siem
```

2. Build the project:

```bash
go build -o cryon
```

3. Run with default configuration:

```bash
./cryon
```

Or specify a custom configuration file:

```bash
./cryon -config custom-config.yaml
```

## Configuration

The system is configured through a YAML file (default: `config.yaml`). Example configuration:

```yaml
general:
  name: Cryon SIEM
  description: Security Information and Event Management System
  version: 0.1.0

logging:
  level: info
  file: cryon.log
  verbose: false

storage:
  type: memory # Options: memory, sqlite, postgres

sources:
  - type: file
    path: /var/log/auth.log
    interval: 10

  - type: syslog
    host: 0.0.0.0
    port: 10514
    interval: 10
```

## Components

### Collector

Handles data collection from various sources:

- File monitoring
- Syslog server
- Windows Event Log
- API endpoints

### Analyzer

Processes security events using:

- Pattern matching rules
- Threshold-based detection
- Event correlation
- Custom rule definitions

### Storage

Supports multiple storage backends:

- In-memory storage (default)
- SQLite (planned)
- PostgreSQL (planned)

### UI

Provides a command-line interface with:

- Real-time event monitoring
- Alert management
- Rule configuration
- System status display

## Command Line Interface

Available commands:

- `status` or `s`: Display system status
- `events` or `e`: View security events
- `alerts` or `a`: Manage alerts
- `rules` or `r`: Configure detection rules
- `config` or `c`: System configuration
- `help` or `?`: Show available commands

## Development Status

This project is currently in prototype stage. Features and APIs may change significantly.

### Planned Features

- [ ] Web interface
- [ ] Authentication and user management
- [ ] Advanced correlation rules
- [ ] Custom dashboards
- [ ] Report generation
- [ ] API integration
- [ ] Plugin system

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is under development and has not yet selected a license.

## Disclaimer

This is a prototype version and should not be used in production environments without proper testing and validation.

## Author

awiones (GitHub: @awiones)

## Acknowledgments

- Go community
- Open source SIEM projects
- Security community
