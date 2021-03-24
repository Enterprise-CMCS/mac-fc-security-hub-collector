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

// ConvertFindingsToCSV - converts select Finding fields to CSV
func (h *HubCollector) ConvertFindingsToCSV(findings []*securityhub.AwsSecurityFinding) error {
	// Try to create the output file we got from the collector object
	f, err := os.Create(h.Outfile)
	if err != nil {
		return err
	}

	// This will automatically close the file when the function completes.
	defer f.Close()

	w := csv.NewWriter(f)
	headers := []string{"Team", "Resource Type", "Title", "Description", "Severity Label", "Remediation Text", "Remediation URL", "Resource ID", "AWS Account ID", "Compliance Status", "Record State"}
	w.Write(headers)
	w.Flush()
	for _, finding := range findings {
		for _, r := range finding.Resources {
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
			w.Write(record)
		}
		w.Flush()
	}

	return nil
}
