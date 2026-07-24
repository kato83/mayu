package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/kato83/mayu/internal/config"
)

var version = "dev"

const defaultDatabaseURL = "postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Parse global --config flag before subcommand dispatch.
	// It can appear anywhere before or after the subcommand name, but for
	// simplicity we scan os.Args for --config=<path> or --config <path>.
	cfg, err := loadGlobalConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		printBanner()
		fmt.Printf("\nmayu %s\n", version)
	case "ingest":
		// Check for sub-subcommand 'history'
		if len(os.Args) > 2 && os.Args[2] == "history" {
			if err := runIngestHistory(os.Args[3:], cfg); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		} else {
			if err := runIngest(os.Args[2:], cfg); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}
	case "search":
		if err := runSearch(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "audit":
		exitCode, err := runAudit(os.Args[2:], cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		os.Exit(exitCode)
	case "migrate":
		if err := runMigrate(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := runStatus(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// loadGlobalConfig parses global flags (--config) from os.Args and loads the
// configuration file. The --config flag can appear anywhere in the arguments.
func loadGlobalConfig() (*config.Config, error) {
	var configPath string
	var explicit bool

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			explicit = true
			break
		}
		if strings.HasPrefix(arg, "--config=") {
			configPath = strings.TrimPrefix(arg, "--config=")
			explicit = true
			break
		}
	}

	if configPath == "" {
		configPath = config.DefaultPath()
	}

	if configPath == "" {
		// Cannot determine home directory — skip config loading.
		return &config.Config{}, nil
	}

	return config.Load(configPath, explicit)
}

func printUsage() {
	printBanner()
	fmt.Println()
	fmt.Println("Usage: mayu [global options] <command> [options]")
	fmt.Println()
	fmt.Println("Global Options:")
	fmt.Println("  --config <path>  Path to config file (default: $HOME/.config/mayu/config.yaml)")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  ingest     Import vulnerability data from OSV, NVD, MITRE, EPSS, KEV")
	fmt.Println("  ingest history  Show ingest job history")
	fmt.Println("  search     Search for vulnerabilities")
	fmt.Println("  audit      Audit SBOM for known vulnerabilities")
	fmt.Println("  serve      Start the API server")
	fmt.Println("  status     Show data source sync status")
	fmt.Println("  migrate    Run database migrations")
	fmt.Println("  version    Print version information")
	fmt.Println("  help       Show this help message")
	fmt.Println()
	fmt.Println("Run 'mayu <command> --help' for more information on a command.")
}

// resolveDatabaseURL determines the database URL from env, config file, or default.
// Priority: environment variable > config file > default.
func resolveDatabaseURL(cfg *config.Config) string {
	if envURL := os.Getenv("DATABASE_URL"); envURL != "" {
		warnInsecureDatabaseURL(envURL)
		return envURL
	}
	if cfg != nil && cfg.DatabaseURL != "" {
		warnInsecureDatabaseURL(cfg.DatabaseURL)
		return cfg.DatabaseURL
	}
	return defaultDatabaseURL
}

// warnInsecureDatabaseURL prints a warning to stderr when connecting to a
// non-local database without TLS (sslmode=disable or unset). Plaintext
// connections to remote hosts expose credentials and data in transit.
func warnInsecureDatabaseURL(dbURL string) {
	insecure, host, sslmode := isInsecureRemoteURL(dbURL)
	if insecure {
		fmt.Fprintf(os.Stderr,
			"warning: connecting to remote database host %q without enforced TLS (sslmode=%q). "+
				"Use sslmode=require (or verify-full) for production connections.\n",
			host, sslmode)
	}
}

// isInsecureRemoteURL reports whether dbURL targets a non-local host without
// enforced TLS. It returns the decision along with the parsed host and sslmode
// for diagnostics. Unparseable URLs are treated as not-insecure (the driver
// will surface the error later).
func isInsecureRemoteURL(dbURL string) (insecure bool, host, sslmode string) {
	u, err := url.Parse(dbURL)
	if err != nil {
		return false, "", ""
	}

	host = u.Hostname()
	if isLocalHost(host) {
		return false, host, u.Query().Get("sslmode")
	}

	sslmode = u.Query().Get("sslmode")
	switch sslmode {
	case "", "disable", "allow", "prefer":
		return true, host, sslmode
	}
	return false, host, sslmode
}

// isLocalHost reports whether the host refers to the local machine.
func isLocalHost(host string) bool {
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
