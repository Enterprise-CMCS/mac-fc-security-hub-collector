package securityhubcollector

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/CMSGov/security-hub-collector/internal/aws/client"
	"github.com/CMSGov/security-hub-collector/pkg/teams"

	"encoding/csv"
	"os"

	"github.com/benbjohnson/clock"
)

// HubCollector is a generic struct used to hold setting info
type HubCollector struct {
	outputFile *os.File
	csvWriter  *csv.Writer
}

// convert all control characters that might break CSV parsing in QuickSight to spaces
func sanitizeFieldForCSV(field string) string {
	var builder strings.Builder
	builder.Grow(len(field))
	for _, r := range field {
		if r >= 32 && r <= 126 {
			builder.WriteRune(r) // Keep printable ASCII
		} else {
			builder.WriteRune(' ') // Everything else becomes space
		}
	}
	return strings.TrimSpace(builder.String())
}

func standardizeTimestamp(timestamp string) string {
	// this is the custom time format that includes outliers we've seen in Security Hub findings
	//  - time zone
	//  - microseconds
	// we'll need to update this if we notice that Quicksight is skipping a lot of rows
	// due to MALFORMED_DATE errors when it ingests the data

	t, err := time.Parse("2006-01-02T15:04:05.999999Z07:00", timestamp)
	if err != nil {
		log.Printf("could not standardize the date string %s", timestamp)
		return timestamp
	}

	// standardize to a Quicksight-friendly format
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// Initialize sets up the HubCollector object and writes the header row to the output file.
func (h *HubCollector) Initialize(outputFileName string) error {
	if h.isInitialized() {
		return fmt.Errorf("HubCollector is already initialized")
	}

	// create the output file and CSV writer
	f, err := os.Create(filepath.Clean(outputFileName))
	if err != nil {
		return fmt.Errorf("could not create output file: %v", err)
	}
	h.outputFile = f
	h.csvWriter = csv.NewWriter(h.outputFile)
	// use tab delimiters since we were seeing some INCORRECT_FIELD_COUNT
	// errors on QuickSight ingestion due to unescaped commas in some fields
	h.csvWriter.Comma = '\t'

	err = h.writeHeadersToOutput()
	if err != nil {
		return fmt.Errorf("could not write headers to output file: %v", err)
	}

	return nil
}

// isInitialized checks if the HubCollector has the required properties to perform file IO
func (h *HubCollector) isInitialized() bool {
	return h.outputFile != nil && h.csvWriter != nil
}

// FlushAndClose flushes the CSV writer and closes the output file
func (h *HubCollector) FlushAndClose() error {
	if !h.isInitialized() {
		return fmt.Errorf("HubCollector is not initialized")
	}

	h.csvWriter.Flush()
	err := h.csvWriter.Error()
	if err != nil {
		return fmt.Errorf("could not flush CSV writer: %v", err)
	}
	h.csvWriter = nil

	err = h.outputFile.Close()
	if err != nil {
		return fmt.Errorf("could not close output file: %v", err)
	}
	h.outputFile = nil

	return nil
}

// GetFindingsAndWriteToOutput - gets all security hub findings from a single AWS account and writes them to the output file
func (h *HubCollector) GetFindingsAndWriteToOutput(secHubRegion, teamName string, account teams.Account) error {
	// We want all the security findings that are active and not resolved.
	params := &securityhub.GetFindingsInput{
		Filters: &types.AwsSecurityFindingFilters{
			RecordState: []types.StringFilter{
				{
					Comparison: types.StringFilterComparisonEquals,
					Value:      aws.String(string(types.RecordStateActive)),
				},
			},
			WorkflowStatus: []types.StringFilter{
				{
					Comparison: types.StringFilterComparisonNotEquals,
					Value:      aws.String(string(types.WorkflowStatusResolved)),
				},
			},
		},
		MaxResults: 100,
	}

	securityHubClient, err := client.MakeSecurityHubClient(secHubRegion, account.RoleARN)
	if err != nil {
		return fmt.Errorf("could not make security hub client: %s", err)
	}
	paginator := securityhub.NewGetFindingsPaginator(securityHubClient, params)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return fmt.Errorf("could not get next page of findings: %s", err)
		}
		err = h.writeFindingsToOutput(page.Findings, teamName, account.Environment)
		if err != nil {
			return fmt.Errorf("could not write findings to output: %s", err)
		}
	}

	return nil
}

type FindingRecord struct {
	Team             string `csv:"Team"`
	ResourceType     string `csv:"Resource Type"`
	Title            string `csv:"Title"`
	Description      string `csv:"Description"`
	SeverityLabel    string `csv:"Severity Label"`
	RemediationText  string `csv:"Remediation Text"`
	RemediationURL   string `csv:"Remediation URL"`
	ResourceID       string `csv:"Resource ID"`
	AWSAccountID     string `csv:"AWS Account ID"`
	ComplianceStatus string `csv:"Compliance Status"`
	RecordState      string `csv:"Record State"`
	WorkflowStatus   string `csv:"Workflow Status"`
	CreatedAt        string `csv:"Created At"`
	UpdatedAt        string `csv:"Updated At"`
	Region           string `csv:"Region"`
	Environment      string `csv:"Environment"`
	Product          string `csv:"Product"`
	DateCollected    string `csv:"Date Collected"`
}

// GetHeaders returns a slice of header names from the CSV tags of the struct fields.
// If a field doesn't have a CSV tag, it falls back to using the field name.
func (FindingRecord) GetHeaders() []string {
	t := reflect.TypeOf(FindingRecord{})
	headers := make([]string, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if csvHeader := field.Tag.Get("csv"); csvHeader != "" {
			headers[i] = csvHeader
		} else {
			headers[i] = field.Name
		}
	}

	return headers
}

func (r FindingRecord) ToSanitizedSlice() []string {
	v := reflect.ValueOf(r)
	slice := make([]string, v.NumField())

	for i := 0; i < v.NumField(); i++ {
		fieldValue := v.Field(i)
		// Since all fields in FindingRecord are strings, we can safely convert and sanitize
		slice[i] = sanitizeFieldForCSV(fieldValue.String())
	}

	return slice
}

// convertFindingToRows - converts a single finding to the record format we're using
func (h *HubCollector) convertFindingToRows(finding types.AwsSecurityFinding, teamName, environment string, clock clock.Clock) [][]string {
	var output [][]string

	for _, r := range finding.Resources {
		region := ""
		if r.Region != nil {
			region = *r.Region
		} else if finding.Region != nil {
			region = *finding.Region
		}

		record := FindingRecord{
			Team:          teamName,
			ResourceType:  *r.Type,
			Title:         *finding.Title,
			Description:   *finding.Description,
			ResourceID:    *r.Id,
			AWSAccountID:  *finding.AwsAccountId,
			RecordState:   string(finding.RecordState),
			CreatedAt:     standardizeTimestamp(*finding.CreatedAt),
			UpdatedAt:     standardizeTimestamp(*finding.UpdatedAt),
			Region:        region,
			Environment:   environment,
			Product:       *finding.ProductName,
			DateCollected: clock.Now().Format("01-02-2006"),
		}

		// Handle optional fields with nil checks
		if finding.Severity != nil {
			record.SeverityLabel = string(finding.Severity.Label)
		}

		if finding.Remediation != nil && finding.Remediation.Recommendation != nil {
			if finding.Remediation.Recommendation.Text != nil {
				record.RemediationText = *finding.Remediation.Recommendation.Text
			}
			if finding.Remediation.Recommendation.Url != nil {
				record.RemediationURL = *finding.Remediation.Recommendation.Url
			}
		}

		if finding.Compliance != nil {
			record.ComplianceStatus = string(finding.Compliance.Status)
		}

		if finding.Workflow != nil {
			record.WorkflowStatus = string(finding.Workflow.Status)
		}

		output = append(output, record.ToSanitizedSlice())
	}

	return output
}

// writeHeadersToOutput - writes headers to the output CSV file
func (h *HubCollector) writeHeadersToOutput() error {
	if !h.isInitialized() {
		return fmt.Errorf("HubCollector is not initialized")
	}
	return h.csvWriter.Write(FindingRecord{}.GetHeaders())
}

// writeFindingsToOutput - takes a list of security findings and writes them to the output file.
func (h *HubCollector) writeFindingsToOutput(findings []types.AwsSecurityFinding, teamName, environment string) error {
	if !h.isInitialized() {
		return fmt.Errorf("HubCollector is not initialized")
	}

	for _, finding := range findings {
		clock := clock.New()
		records := h.convertFindingToRows(finding, teamName, environment, clock)
		for _, record := range records {
			err := h.csvWriter.Write(record)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
