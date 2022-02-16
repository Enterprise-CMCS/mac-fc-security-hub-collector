package securityhubcollector

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"

	"go.uber.org/zap"

	"encoding/csv"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// HubCollector is a generic struct used to hold setting info
type HubCollector struct {
	Logger    *zap.Logger
	HubClient securityhubiface.SecurityHubAPI
	Outfile   string
	AcctMap   map[string]string
}

// Teams is a struct describing the format we expect in the JSON file
// describing the team mappings
type Teams struct {
	Teams []Team `json:"teams"`
}

// Team is a struct describing a single team and its accounts as we
// expect in the JSON file describing team mappings
type Team struct {
	Name     string   `json:"name"`
	Accounts []string `json:"accounts"`
	Profiles []string `json:"profiles"`
}

// ReadTeamMap - takes the JSON encoded file that maps teams to accounts
// and converts it into a Teams object that we can use later.
func ReadTeamMap(jsonFile string) (jsonTeams Teams, err error) {
	jsonFile = filepath.Clean(jsonFile)

	// gosec complains here because we're essentially letting you open
	// any file you want, which if this was a webapp would be pretty
	// sketchy. However, since this is a CLI tool, and you shouldn't be
	// able to open a file you don't have permission for anyway, we can
	// safely ignore its complaints here.
	// #nosec
	f, err := os.Open(jsonFile)

	defer func() {
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
	}()

	err = json.NewDecoder(f).Decode(&jsonTeams)

	return

}

// BuildAcctMap - builds a map of accounts to teams from a map of teams
// to accounts. The JSON file (and the Teams object we extract from it)
// maps teams to a list of accounts (because that is easiest for humans),
// but what we really want for building our output is to have a mapping
// of accounts to teams, because accounts are what we actually get from
// the security hub finding.
func BuildAcctMap(jsonTeams Teams) map[string]string {
	acctMap := make(map[string]string)

	for _, team := range jsonTeams.Teams {
		for _, acct := range team.Accounts {
			acctMap[acct] = team.Name
		}
	}

	return acctMap
}

// BuildProfileList - builds a list of all the AWS profiles to use to gather data
func BuildProfileList(jsonTeams Teams) []string {
	var profileList []string

	for _, team := range jsonTeams.Teams {
		for _, profile := range team.Profiles {
			profileList = append(profileList, profile)
		}
	}

	return profileList
}

// WriteFindingsToS3 - Writes the finding results file to an S3 bucket
func WriteFindingsToS3(s3uploader *s3manager.Uploader, s3bucket string, s3key string, outfile string) (err error) {
	// if we got a bucket, let's try to upload
	if s3bucket != "" {

		// use Outfile name as the key by default
		key := outfile
		// if the passed in key exists, use that
		if s3key != "" {
			key = s3key
		}

		// Carve up things and throw in timestamp in the key
		current := time.Now()
		suffix := current.Format("2006-01-02_15.04.05")
		ext := path.Ext(key)
		fn := strings.TrimSuffix(key, ext)
		key = fn + "_" + suffix + ext

		// open our local file for reading
		f, err := os.Open(outfile) //nolint
		if err != nil {
			return err
		}

		// This will automatically close the file when the function completes.
		defer func() {
			cerr := f.Close()
			if err == nil {
				err = cerr
			}
		}()

		upParams := &s3manager.UploadInput{
			Bucket: aws.String(s3bucket),
			Key:    aws.String(key),
			Body:   f,
		}
		_, err = s3uploader.Upload(upParams)
		return err
	}

	return
}

// GetSecurityHubFindings - gets all security hub findings from a single AWS account
func (h *HubCollector) GetSecurityHubFindings() ([]*securityhub.AwsSecurityFinding, error) {
	var outputList []*securityhub.AwsSecurityFinding

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
		record = append(record, h.AcctMap[*finding.AwsAccountId])
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

// WriteFindingsToOutput - takes a list of security
func (h *HubCollector) WriteFindingsToOutput(findings []*securityhub.AwsSecurityFinding, writeHeaders bool) (err error) {
	var f *os.File
	if writeHeaders {
		// Try to create the output file we got from the collector object
		f, err = os.Create(h.Outfile)
		if err != nil {
			return err
		}
	} else {
		f, err = os.OpenFile(h.Outfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
	}

	// This will automatically close the file when the function completes.
	defer func() {
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
	}()

	w := csv.NewWriter(f)

	if writeHeaders {
		// For now, we're hardcoding the headers; in the future, if it turned
		// out the data we wanted from these findings changed regularly, w
		// could make the headers/fields come from some sort of schema or struct,
		// but for now this is good enough.
		headers := []string{"Team", "Resource Type", "Title", "Description", "Severity Label", "Remediation Text", "Remediation URL", "Resource ID", "AWS Account ID", "Compliance Status", "Record State", "Workflow Status", "Created At", "Updated At"}

		err = w.Write(headers)
		if err != nil {
			return err
		}
		w.Flush()
	}

	// For each finding, we put it through the conversion function, which
	// can generate multiple rows (due to multiple resources. For each row,
	// we write it to the file and be done with it.
	for _, finding := range findings {
		records := h.ConvertFindingToRows(finding)
		for _, record := range records {
			err = w.Write(record)
			if err != nil {
				return err
			}
			w.Flush()
		}
	}

	return
}
