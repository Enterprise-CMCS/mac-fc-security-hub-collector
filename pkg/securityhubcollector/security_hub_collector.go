package securityhubcollector

import (
	"context"
	"fmt"
	"path/filepath"

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

// convertFindingToRows - converts a single finding to the record format we're using
// the order of the records must match with the order of the headers in writeHeadersToOutput
func (h *HubCollector) convertFindingToRows(finding types.AwsSecurityFinding, teamName, environment string, clock clock.Clock) [][]string {
	var output [][]string

	// Each finding may have multiple resources, so we need to iterate through
	// them and pull the relevant bits; we will create two lines for a single
	// finding that has two resources, with only the resource different.
	for _, r := range finding.Resources {
		// Here we compile a single record, which is a representation of
		// the row we want to output into the CSV for this resource in
		// the finding.

		// If the resource for a finding has a non-nil region, prefer that. Otherwise use the finding region.  If both are nil, use an empty string.
		var region string
		if r.Region != nil {
			region = *r.Region
		} else if finding.Region != nil {
			region = *finding.Region
		}

		var record []string
		record = append(record, teamName)
		record = append(record, *r.Type)
		record = append(record, *finding.Title)
		record = append(record, *finding.Description)
		if finding.Severity == nil {
			record = append(record, "")
		} else {
			record = append(record, string(finding.Severity.Label))
		}
		if finding.Remediation == nil {
			record = append(record, "", "")
		} else {
			if finding.Remediation.Recommendation == nil {
				record = append(record, "", "")
			} else {
				if finding.Remediation.Recommendation.Text == nil {
					record = append(record, "")
				} else {
					record = append(record, *finding.Remediation.Recommendation.Text)
				}
				if finding.Remediation.Recommendation.Url == nil {
					record = append(record, "")
				} else {
					record = append(record, *finding.Remediation.Recommendation.Url)
				}
			}
		}
		record = append(record, *r.Id)
		record = append(record, *finding.AwsAccountId)
		if finding.Compliance == nil {
			record = append(record, "")
		} else {
			record = append(record, string(finding.Compliance.Status))
		}
		record = append(record, string(finding.RecordState))
		if finding.Workflow == nil {
			record = append(record, "")
		} else {
			record = append(record, string(finding.Workflow.Status))
		}
		record = append(record, *finding.CreatedAt)
		record = append(record, *finding.UpdatedAt)
		record = append(record, region)
		record = append(record, environment)
		record = append(record, *finding.ProductName)
		record = append(record, clock.Now().Format("01-02-2006"))

		// Each record *may* have multiple findings, so we make a list of
		// records and that's what we'll output.
		output = append(output, record)
	}

	return output
}

// writeHeadersToOutput - writes headers to the output CSV file
func (h *HubCollector) writeHeadersToOutput() error {
	if !h.isInitialized() {
		return fmt.Errorf("HubCollector is not initialized")
	}

	// For now, we're hardcoding the headers; in the future, if it turned
	// out the data we wanted from these findings changed regularly, we
	// could make the headers/fields come from some sort of schema or struct,
	// but for now this is good enough.
	headers := []string{"Team", "Resource Type", "Title", "Description", "Severity Label", "Remediation Text", "Remediation URL", "Resource ID", "AWS Account ID", "Compliance Status", "Record State", "Workflow Status", "Created At", "Updated At", "Region", "Environment", "Product", "Date Collected"}

	err := h.csvWriter.Write(headers)
	if err != nil {
		return err
	}

	return nil
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
