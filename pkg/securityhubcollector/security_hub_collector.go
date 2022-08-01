package securityhubcollector

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"

	"github.com/CMSGov/security-hub-collector/internal/aws/client"

	"encoding/csv"
	"os"
)

// HubCollector is a generic struct used to hold setting info
type HubCollector struct {
	HubClient  securityhubiface.SecurityHubAPI
	OutputFile *os.File
	CSVWriter  *csv.Writer
}

// Initialize sets up the HubCollector object and writes the header row to the output file.
func (h *HubCollector) Initialize(outputFileName string) error {
	if h.isInitialized() {
		return fmt.Errorf("HubCollector is already initialized")
	}

	// create the output file and CSV writer
	f, err := os.Create(outputFileName)
	if err != nil {
		return fmt.Errorf("could not create output file: %v", err)
	}
	h.OutputFile = f
	h.CSVWriter = csv.NewWriter(h.OutputFile)

	err = h.writeHeadersToOutput()
	if err != nil {
		return fmt.Errorf("could not write headers to output file: %v", err)
	}

	return nil
}

// isInitialized checks if the HubCollector has the required properties to perform file IO
func (h *HubCollector) isInitialized() bool {
	return h.OutputFile != nil && h.CSVWriter != nil
}

// FlushAndClose flushes the CSV writer and closes the output file
func (h *HubCollector) FlushAndClose() error {
	if !h.isInitialized() {
		return fmt.Errorf("HubCollector is not initialized")
	}

	h.CSVWriter.Flush()
	err := h.CSVWriter.Error()
	if err != nil {
		return fmt.Errorf("could not flush CSV writer: %v", err)
	}
	h.CSVWriter = nil

	err = h.OutputFile.Close()
	if err != nil {
		return fmt.Errorf("could not close output file: %v", err)
	}
	h.OutputFile = nil

	return nil
}

// GetFindingsAndWriteToOutput - gets all security hub findings from a single AWS account and writes them to the output file
func (h *HubCollector) GetFindingsAndWriteToOutput(region string, profile string, roleArn string, teamName string) error {
	// We want all the security findings that are active and not resolved.
	params := &securityhub.GetFindingsInput{
		Filters: &securityhub.AwsSecurityFindingFilters{
			RecordState: []*securityhub.StringFilter{
				{
					Comparison: aws.String("EQUALS"),
					Value:      aws.String("ACTIVE"),
				},
			},
			WorkflowStatus: []*securityhub.StringFilter{
				{
					Comparison: aws.String("NOT_EQUALS"),
					Value:      aws.String("RESOLVED"),
				},
			},
		},
		MaxResults: aws.Int64(100),
	}

	var err error
	securityHubClient := client.SecurityHub(region, profile, roleArn)

	err = securityHubClient.GetFindingsPages(params,
		func(page *securityhub.GetFindingsOutput, lastPage bool) bool {
			writeErr := h.writeFindingsToOutput(page.Findings, teamName)
			if writeErr != nil {
				err = fmt.Errorf("could not write findings to output: %s", writeErr)
				return false
			}
			return true
		})

	return err
}

// convertFindingToRows - converts a single finding to the record format we're using
func (h *HubCollector) convertFindingToRows(finding *securityhub.AwsSecurityFinding, teamName string) [][]string {
	var output [][]string

	// Each finding may have multiple resources, so we need to iterate through
	// them and pull the relevant bits; we will create two lines for a single
	// finding that has two resources, with only the resource different.
	for _, r := range finding.Resources {
		// Here we compile a single record, which is a representation of
		// the row we want to output into the CSV for this resource in
		// the finding.
		var record []string
		record = append(record, teamName)
		record = append(record, *r.Type)
		record = append(record, *finding.Title)
		record = append(record, *finding.Description)
		if finding.Severity == nil {
			record = append(record, "")
		} else {
			record = append(record, *finding.Severity.Label)
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
			record = append(record, *finding.Compliance.Status)
		}
		record = append(record, *finding.RecordState)
		if finding.Workflow == nil {
			record = append(record, "")
		} else {
			record = append(record, *finding.Workflow.Status)
		}
		record = append(record, *finding.CreatedAt)
		record = append(record, *finding.UpdatedAt)

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
	headers := []string{"Team", "Resource Type", "Title", "Description", "Severity Label", "Remediation Text", "Remediation URL", "Resource ID", "AWS Account ID", "Compliance Status", "Record State", "Workflow Status", "Created At", "Updated At"}

	err := h.CSVWriter.Write(headers)
	if err != nil {
		return err
	}

	return nil
}

// writeFindingsToOutput - takes a list of security findings and writes them to the output file.
func (h *HubCollector) writeFindingsToOutput(findings []*securityhub.AwsSecurityFinding, teamName string) error {
	if !h.isInitialized() {
		return fmt.Errorf("HubCollector is not initialized")
	}

	for _, finding := range findings {
		records := h.convertFindingToRows(finding, teamName)
		for _, record := range records {
			err := h.CSVWriter.Write(record)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
