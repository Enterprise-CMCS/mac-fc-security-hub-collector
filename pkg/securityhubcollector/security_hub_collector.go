package securityhubcollector

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"

	"go.uber.org/zap"

	"encoding/csv"
	"os"
)

// HubCollector is a generic struct used to hold setting info
type HubCollector struct {
	Logger    *zap.Logger
	HubClient securityhubiface.SecurityHubAPI
	Outfile   string
}

// GetSecurityHubFindings - gets all security hub findings from a single AWS account
func (h *HubCollector) GetSecurityHubFindings() ([]*securityhub.AwsSecurityFinding, error) {
	var outputList []*securityhub.AwsSecurityFinding

	// We want all the security findings that are active and not resolved.
	params := &securityhub.GetFindingsInput{
		Filters: &securityhub.AwsSecurityFindingFilters{
			RecordState: []*securityhub.StringFilter{
				&securityhub.StringFilter{
					Comparison: aws.String("EQUALS"),
					Value:      aws.String("ACTIVE"),
				},
			},
			WorkflowStatus: []*securityhub.StringFilter{
				&securityhub.StringFilter{
					Comparison: aws.String("NOT_EQUALS"),
					Value:      aws.String("RESOLVED"),
				},
			},
		},
	}

	err := h.HubClient.GetFindingsPages(params,
		func(page *securityhub.GetFindingsOutput, lastPage bool) bool {
			outputList = append(outputList, page.Findings...)
			return true
		})

	if err != nil {
		return nil, err
	}

	return outputList, nil
}

// ConvertFindingToRows - converts a single finding to the record format we're using
func (h *HubCollector) ConvertFindingToRows(finding *securityhub.AwsSecurityFinding) [][]string {
	var output [][]string

	// Each finding may have multiple resources, so we need to iterate through
	// them and pull the relevant bits; we will create two lines for a single
	// finding that has two resources, with only the resource different.
	for _, r := range finding.Resources {
		// Here we compile a single record, which is a representation of
		// the row we want to output into the CSV for this resource in
		// the finding.
		var record []string
		record = append(record, "Team TBD")
                record = append(record, *r.Type)
                record = append(record, *finding.Title)
                record = append(record, *finding.Description)
                record = append(record, *finding.Severity.Label)
                record = append(record, *finding.Remediation.Recommendation.Text)
                record = append(record, *finding.Remediation.Recommendation.Url)
                record = append(record, *r.Id)
                record = append(record, *finding.AwsAccountId)
                record = append(record, *finding.Compliance.Status)
                record = append(record, *finding.RecordState)

		// Each record *may* have multiple findings, so we make a list of
		// records and that's what we'll output.
		output = append(output, record)
	}

	return output

}

// WriteFindingsToOutput - takes a list of security
func (h *HubCollector) WriteFindingsToOutput(findings []*securityhub.AwsSecurityFinding) error {
	// Try to create the output file we got from the collector object
	f, err := os.Create(h.Outfile)
	if err != nil {
		return err
	}

	// This will automatically close the file when the function completes.
	defer f.Close()

	w := csv.NewWriter(f)

	// For now, we're hardcoding the headers; in the future, if it turned
	// out the data we wanted from these findings changed regularly, w
	// could make the headers/fields come from some sort of schema or struct,
	// but for now this is good enough.
	headers := []string{"Team", "Resource Type", "Title", "Description", "Severity Label", "Remediation Text", "Remediation URL", "Resource ID", "AWS Account ID", "Compliance Status", "Record State"}
	w.Write(headers)
	w.Flush()

	// For each finding, we put it through the conversion function, which
	// can generate multiple rows (due to multiple resources. For each row,
	// we write it to the file and be done with it.
	for _, finding := range findings {
		records := h.ConvertFindingToRows(finding)
		for _, record := range records {
			w.Write(record)
			w.Flush()
		}
	}

	return nil
}
