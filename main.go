package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/CMSGov/security-hub-collector/internal/aws/client"
	"github.com/CMSGov/security-hub-collector/pkg/helpers"
	"github.com/CMSGov/security-hub-collector/pkg/securityhubcollector"
	"github.com/CMSGov/security-hub-collector/pkg/teams"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	flag "github.com/jessevdk/go-flags"

	"log"
)

// Options describes the command line options available.
type Options struct {
	AssumeRole         string   `short:"a" long:"assume-role" required:"true" description:"Role name to assume when collecting across all accounts."`
	OutputFileName     string   `short:"o" long:"output" required:"false" description:"File to direct output to." default:"SecurityHub-Findings.csv"`
	S3Region           string   `short:"s" long:"s3-region" env:"AWS_REGION" required:"false" description:"AWS region to use for s3 uploads."`
	SecurityHubRegions []string `short:"r" long:"sechub-regions" required:"false" default:"us-east-1" default:"us-west-2" description:"AWS regions to use for Security Hub findings."`
	S3Bucket           string   `short:"b" long:"s3-bucket" required:"false" description:"S3 bucket to use to upload results. Optional, if not provided, results will not be uploaded to S3."`
	S3Key              string   `short:"k" long:"s3-key" required:"false" description:"S3 bucket key, or path, to use to upload results."`
	TeamMapFile        string   `short:"m" long:"team-map" required:"true" description:"JSON file containing team to account mappings."`
}

var options Options

// WriteFindingsToS3 - Writes the finding results file to an S3 bucket
func writeFindingsToS3() error {
	s3uploader := client.MustMakeS3Uploader(options.S3Region)
	// use Outfile name as the key by default
	key := options.OutputFileName
	// if the passed in key exists, use that
	if options.S3Key != "" {
		key = options.S3Key
	}

	// Carve up things and throw in timestamp in the key
	current := time.Now()
	suffix := current.Format("2006-01-02_15.04.05")
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

// collectFindings is doing the bulk of our work here; it reads in the
// team map JSON file, builds the HubCollector object, writes headers to the output file, and processes findings
// depending on the definitions in the team map and the CLI options.
func collectFindings(secHubRegions []string) {
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

	accountsToTeams, err := teams.ParseTeamMap(options.TeamMapFile)
	if err != nil {
		log.Fatalf("could not parse team map file: %v", err)
	}

	for account, teamName := range accountsToTeams {
		roleArn := fmt.Sprintf("arn:aws:iam::%v:role/%v", account.ID, options.AssumeRole)

		for _, secHubRegion := range secHubRegions {
			log.Printf("getting findings for account %v in %v", account.ID, secHubRegion)
			err = h.GetFindingsAndWriteToOutput(secHubRegion, teamName, account.Environment, roleArn)
			if err != nil {
				log.Fatalf("could not get findings for account %v in %v: %v", account.ID, secHubRegion, err)
			}
		}
	}
}

func main() {
	parser := flag.NewParser(&options, flag.Default)
	_, err := parser.Parse()
	if err != nil {
		log.Fatalf("could not parse options: %v", err)
	}

	collectFindings(options.SecurityHubRegions)

	if options.S3Bucket != "" {
		err := writeFindingsToS3()
		if err != nil {
			log.Fatalf("could not upload findings to S3: %v", err)
		}
	}
}
