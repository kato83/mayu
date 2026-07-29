package notification

import "embed"

//go:embed templates/slack.json.tmpl
var slackTemplate string

//go:embed templates/teams.json.tmpl
var teamsTemplate string

//go:embed templates/email.html.tmpl
var emailHTMLTemplate string

// TemplateName represents a preset notification template.
type TemplateName string

const (
	TemplateSlack TemplateName = "slack"
	TemplateTeams TemplateName = "teams"
	TemplateEmail TemplateName = "email"
)

// TemplateInfo holds metadata about a preset template.
type TemplateInfo struct {
	Name        TemplateName
	Description string
	ContentType string
	Template    string
}

// PresetTemplates returns all available preset notification templates.
func PresetTemplates() []TemplateInfo {
	return []TemplateInfo{
		{
			Name:        TemplateSlack,
			Description: "Slack Block Kit JSON template for incoming webhooks",
			ContentType: "application/json",
			Template:    slackTemplate,
		},
		{
			Name:        TemplateTeams,
			Description: "Microsoft Teams Adaptive Card template for incoming webhooks",
			ContentType: "application/json",
			Template:    teamsTemplate,
		},
		{
			Name:        TemplateEmail,
			Description: "HTML email template for vulnerability alerts",
			ContentType: "text/html",
			Template:    emailHTMLTemplate,
		},
	}
}

// GetSlackTemplate returns the Slack Block Kit JSON template.
// This can be used directly as a webhook body_template value.
func GetSlackTemplate() string {
	return slackTemplate
}

// GetTeamsTemplate returns the Microsoft Teams Adaptive Card template.
// This can be used directly as a webhook body_template value.
func GetTeamsTemplate() string {
	return teamsTemplate
}

// GetEmailHTMLTemplate returns the HTML email template.
// Used by EmailSender for rich email notifications.
func GetEmailHTMLTemplate() string {
	return emailHTMLTemplate
}

// TemplateFS provides direct access to the embedded template filesystem
// for advanced use cases.
//
//go:embed templates
var TemplateFS embed.FS
