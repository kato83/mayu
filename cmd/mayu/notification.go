package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/notification"
)

func runNotification(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printNotificationUsage()
		return fmt.Errorf("no subcommand specified (use 'templates' or 'test-email')")
	}

	switch args[0] {
	case "templates":
		return runNotificationTemplates(args[1:])
	case "test-email":
		return runNotificationTestEmail(args[1:], cfg)
	case "help", "-h", "--help":
		printNotificationUsage()
		return nil
	default:
		printNotificationUsage()
		return fmt.Errorf("unknown notification subcommand: %q (use 'templates' or 'test-email')", args[0])
	}
}

func runNotificationTemplates(args []string) error {
	fs := flag.NewFlagSet("notification templates", flag.ContinueOnError)
	format := fs.String("format", "table", "Output format: table, json")
	name := fs.String("name", "", "Show full template content for a specific template (slack, teams, email)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu notification templates [options]")
		fmt.Println()
		fmt.Println("List available preset notification templates.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu notification templates")
		fmt.Println("  mayu notification templates --name slack")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	templates := notification.PresetTemplates()

	// If a specific template is requested, show its full content.
	if *name != "" {
		for _, tmpl := range templates {
			if string(tmpl.Name) == *name {
				fmt.Println(tmpl.Template)
				return nil
			}
		}
		return fmt.Errorf("unknown template: %q (available: slack, teams, email)", *name)
	}

	switch *format {
	case "json":
		fmt.Println("[")
		for i, tmpl := range templates {
			comma := ","
			if i == len(templates)-1 {
				comma = ""
			}
			fmt.Printf("  {\"name\": %q, \"description\": %q, \"content_type\": %q}%s\n",
				tmpl.Name, tmpl.Description, tmpl.ContentType, comma)
		}
		fmt.Println("]")
	default:
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintf(w, "NAME\tDESCRIPTION\tCONTENT-TYPE\n")
		for _, tmpl := range templates {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", tmpl.Name, tmpl.Description, tmpl.ContentType)
		}
		return w.Flush()
	}
	return nil
}

func runNotificationTestEmail(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("notification test-email", flag.ContinueOnError)
	to := fs.String("to", "", "Recipient email address (required)")
	subject := fs.String("subject", "Mayu Test Email Notification", "Email subject")

	fs.Usage = func() {
		fmt.Println("Usage: mayu notification test-email --to <email>")
		fmt.Println()
		fmt.Println("Send a test email to verify SMTP configuration.")
		fmt.Println("Requires notification.email configuration in config.yaml.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu notification test-email --to user@example.com")
		fmt.Println("  mayu notification test-email --to user@example.com --subject 'Custom Subject'")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *to == "" {
		return fmt.Errorf("--to is required")
	}

	emailCfg := cfg.Notification.Email
	if !emailCfg.Enabled {
		return fmt.Errorf("email notification is not enabled in configuration (set notification.email.enabled: true)")
	}
	if emailCfg.SMTPHost == "" {
		return fmt.Errorf("SMTP host is not configured (set notification.email.smtp_host)")
	}

	port := emailCfg.SMTPPort
	if port == 0 {
		port = 587
	}

	sender := &notification.EmailSender{
		Host:     emailCfg.SMTPHost,
		Port:     port,
		Username: emailCfg.Username,
		Password: emailCfg.Password,
		From:     emailCfg.From,
		TLS:      emailCfg.TLS,
	}

	// Use a sample HTML body from the email template with test data.
	htmlBody := strings.NewReplacer(
		"{{ID}}", "CVE-0000-0000",
		"{{Severity}}", "MEDIUM",
		"{{EPSS}}", "0.50",
		"{{LEV}}", "0.30",
		"{{Summary}}", "This is a test email notification from Mayu.",
		"{{Event}}", "test",
		"{{URL}}", "http://localhost:8080",
	).Replace(notification.GetEmailHTMLTemplate())

	recipients := strings.Split(*to, ",")
	for i := range recipients {
		recipients[i] = strings.TrimSpace(recipients[i])
	}

	fmt.Printf("Sending test email to %s...\n", *to)
	fmt.Printf("  SMTP: %s:%d\n", emailCfg.SMTPHost, port)
	fmt.Printf("  From: %s\n", emailCfg.From)
	fmt.Printf("  TLS:  %t\n", emailCfg.TLS)
	fmt.Println()

	ctx := context.Background()
	if err := sender.Send(ctx, recipients, *subject, htmlBody); err != nil {
		return fmt.Errorf("send test email: %w", err)
	}

	fmt.Println("Test email sent successfully!")
	return nil
}

func printNotificationUsage() {
	fmt.Println("Usage: mayu notification <subcommand> [options]")
	fmt.Println()
	fmt.Println("Manage notification channels and templates.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  templates     List available preset notification templates")
	fmt.Println("  test-email    Send a test email to verify SMTP configuration")
	fmt.Println()
	fmt.Println("Run 'mayu notification <subcommand> --help' for more information.")
}
