package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/CMSGov/security-hub-collector/internal/aws/client"
	"github.com/CMSGov/security-hub-collector/pkg/helpers"
	"github.com/CMSGov/security-hub-collector/pkg/securityhubcollector"
	"github.com/CMSGov/security-hub-collector/pkg/teams"

	flag "github.com/jessevdk/go-flags"

	"log"
)

// Options describes the command line options available.
type Options struct {
	OutputFileName     string   `short:"o" long:"output" env:"OUTPUT_FILE" required:"false" description:"File to direct output to." default:"SecurityHub-Findings.csv"`
	S3Region           string   `short:"s" long:"s3-region" env:"AWS_REGION" required:"false" description:"AWS region to use for s3 uploads."`
	SecurityHubRegions []string `short:"r" long:"sechub-regions" required:"false" default:"us-east-1" default:"us-west-2" description:"AWS regions to use for Security Hub findings."`
	S3Bucket           string   `short:"b" long:"s3-bucket" required:"false" env:"S3_BUCKET" description:"S3 bucket to use to upload results. Optional, if not provided, results will not be uploaded to S3."`
	S3Key              string   `short:"k" long:"s3-key" required:"false" env:"S3_KEY" description:"S3 bucket key, or path, to use to upload results."`
	Base64TeamMap      string   `short:"m" long:"team-map" required:"false" env:"BASE64_TEAM_MAP" description:"Base64 encoded JSON containing team to account mappings."`
	TeamsAPIBaseURL    string   `long:"teams-api-base-url" required:"false" env:"TEAMS_API_BASE_URL" description:"Base URL of the Teams API, which provides team to account mappings"`
	TeamsAPIKey        string   `long:"teams-api-key" required:"false" env:"TEAMS_API_KEY" description:"API key for the Teams API, which provides team to account mappings"`
	CollectorRolePath  string   `long:"role-path" required:"false" env:"COLLECTOR_ROLE_PATH" description:"Path of the AWS IAM cross-account role that allows the Collector to access Security Hub"`
}

var options Options

// WriteFindingsToS3 - Writes the finding results file to an S3 bucket
func writeFindingsToS3() error {
	s3uploader, err := client.MakeS3Uploader(options.S3Region)
	if err != nil {
		return err
	}
	// use Outfile name as the key by default
	key := options.OutputFileName
	// if the passed in key exists, use that
	if options.S3Key != "" {
		key = options.S3Key
	}

	// Carve up things and throw in timestamp in the key.
	// Use a daily timestamp so that multiple runs in the same day will overwrite
	// the previous run's file with updated results for that day
	current := time.Now()
	suffix := current.Format("01-02-2006")
	ext := path.Ext(key)
	fn := strings.TrimSuffix(key, ext)
	key = fn + "_" + suffix + ext

	// open our local file for reading
	f, err := os.Open(options.OutputFileName) //nolint
	if err != nil {
		return err
	}

	// This will automatically close the file when the function completes.
	defer func() {
		cerr := f.Close()
		if cerr != nil {
			err = helpers.CombineErrors(err, cerr)
		}
	}()

	upParams := &s3.PutObjectInput{
		Bucket: aws.String(options.S3Bucket),
		Key:    aws.String(key),
		Body:   f,
	}
	_, err = s3uploader.Upload(context.TODO(), upParams)
	if err != nil {
		return err
	}
	log.Printf("successfully uploaded findings to s3://%v/%v", options.S3Bucket, key)

	return nil
}

// collectFindings is doing the bulk of our work here; it reads in the team map from the Teams API,
// builds the HubCollector object, writes headers to the output file, and processes findings
// depending on the definitions in the team map and the CLI options.
func collectFindings(secHubRegions []string) error {
	// Check which source to use for team data and validate required fields
	if options.Base64TeamMap == "" && options.TeamsAPIBaseURL == "" {
		return fmt.Errorf("either team map file or Teams API base URL must be specified")
	}
	if options.Base64TeamMap != "" && options.TeamsAPIBaseURL != "" {
		return fmt.Errorf("both team map file and Teams API base URL specified; please use only one source of team map data")
	}
	if options.TeamsAPIBaseURL != "" && options.TeamsAPIKey == "" {
		return fmt.Errorf("Teams API key required when using Teams API")
	}

	h := securityhubcollector.HubCollector{}
	err := h.Initialize(options.OutputFileName)
	if err != nil {
		log.Fatalf("could not initialize HubCollector: %v", err)
	}

	// flush the buffer and close the file when the function completes.
	defer func() {
		ferr := h.FlushAndClose()
		if ferr != nil {
			log.Fatalf("could not flush buffer and close output file: %v", err)
		}
	}()

	var accountsToTeams map[teams.Account]string

	// either get the map from the team map file or from the Teams API, depending on the specified CLI flags
	if options.Base64TeamMap != "" {
		accountsToTeams, err = teams.ParseTeamMap(options.Base64TeamMap)
		if err != nil {
			log.Fatalf("could not parse team map file: %v", err)
		}
	} else {
		accountsToTeams, err = teams.GetTeamsFromTeamsAPI(options.TeamsAPIBaseURL, options.TeamsAPIKey, options.CollectorRolePath)
		if err != nil {
			log.Fatalf("could not load teams from Teams API: %v", err)
		}
	}

	for account, teamName := range accountsToTeams {
		for _, secHubRegion := range secHubRegions {
			log.Printf("getting findings for account %v in %v", account.ID, secHubRegion)
			err = h.GetFindingsAndWriteToOutput(secHubRegion, teamName, account)
			if err != nil {
				log.Fatalf("could not get findings for account %v in %v: %v", account.ID, secHubRegion, err)
			}
		}
	}

	return nil
}

func main() {
	parser := flag.NewParser(&options, flag.Default)
	_, err := parser.Parse()
	if err != nil {
		log.Fatalf("could not parse options: %v", err)
	}

	if err := collectFindings(options.SecurityHubRegions); err != nil {
		log.Fatalf("error collecting findings: %v", err)
	}

	if options.S3Bucket != "" {
		err := writeFindingsToS3()
		if err != nil {
			log.Fatalf("could not upload findings to S3: %v", err)
		}
	}
}
