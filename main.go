package main

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"

	"github.com/CMSGov/security-hub-collector/internal/aws/client"
	"github.com/CMSGov/security-hub-collector/pkg/helpers"
	"github.com/CMSGov/security-hub-collector/pkg/securityhubcollector"
	"github.com/CMSGov/security-hub-collector/pkg/teams"

	flag "github.com/jessevdk/go-flags"

	"log"
)

// Options describes the command line options available.
type Options struct {
	AssumedRole    string `short:"a" long:"assumedrole" required:"false" description:"Role name to assume when collecting across all accounts."`
	OutputFileName string `short:"o" long:"output" required:"false" description:"File to direct output to." default:"SecurityHub-Findings.csv"`
	DefaultProfile string `short:"p" long:"profile" env:"AWS_PROFILE" required:"false" description:"The default AWS profile to use. Overridden if profiles are specified in the team map."`
	Region         string `short:"r" long:"region" env:"AWS_REGION" required:"false" description:"The AWS region to use."`
	S3Bucket       string `short:"s" long:"s3bucket" required:"false" description:"S3 bucket to use to upload results."`
	S3Key          string `short:"k" long:"s3key" required:"false" description:"S3 bucket key, or path, to use to upload results."`
	TeamMapFile    string `short:"m" long:"teammap" required:"true" description:"JSON file containing team to account mappings."`
	UploadFlag     bool   `short:"u" long:"upload-only" description:"Use this flag to upload results to S3"`
}

var options Options

func uploadS3() {
	s3uploader := client.MustMakeS3Uploader(options.Region, options.DefaultProfile)
	err := writeFindingsToS3(s3uploader)
	if err != nil {
		log.Fatalf("could not write output to S3: %v", err)
	}
}

// WriteFindingsToS3 - Writes the finding results file to an S3 bucket
func writeFindingsToS3(s3uploader *s3manager.Uploader) (err error) {
	// if we got a bucket, let's try to upload
	if options.S3Bucket != "" {
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
				err = helpers.CombineErrors([]error{err, cerr})
			}
		}()

		upParams := &s3manager.UploadInput{
			Bucket: aws.String(options.S3Bucket),
			Key:    aws.String(key),
			Body:   f,
		}
		_, err = s3uploader.Upload(upParams)
	}

	return
}

// collectFindings is doing the bulk of our work here; it reads in the
// team map JSON file, builds the HubCollector object, writes headers to the output file, and processes findings
// depending on the definitions in the team map and the CLI options.
func collectFindings() {
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

	profilesToTeams, accountsToTeams, err := teams.ParseTeamMap(options.TeamMapFile)
	if err != nil {
		log.Fatalf("could not parse team map file: %v", err)
	}

	if len(profilesToTeams) > 0 {
		// If we have defined profiles, get findings for each profile
		for profile, teamName := range profilesToTeams {
			log.Printf("getting findings for profile %v", profile)
			err = h.GetFindingsAndWriteToOutput(options.Region, profile, "", teamName)
			if err != nil {
				log.Fatalf("could not get findings for profile %v: %v", profile, err)
			}
		}
	} else if options.AssumedRole != "" {
		// If we have a defined assumed role, get findings for each account in the team map
		for account, teamName := range accountsToTeams {
			log.Printf("getting findings for account %v", account)
			roleArn := fmt.Sprintf("arn:aws:iam::%v:role/%v", account, options.AssumedRole)
			err = h.GetFindingsAndWriteToOutput(options.Region, options.DefaultProfile, roleArn, teamName)
			if err != nil {
				log.Fatalf("could not get findings for account %v: %v", account, err)
			}
		}
	} else {
		// If we have no defined profiles or assumed role, get findings for the default profile
		log.Printf("getting findings for default profile %v", options.DefaultProfile)
		err = h.GetFindingsAndWriteToOutput(options.Region, options.DefaultProfile, "", "")
		if err != nil {
			log.Fatalf("could not get findings: %v", err)
		}
	}
}

func main() {
	// Parse out command line options:
	parser := flag.NewParser(&options, flag.Default)
	_, err := parser.Parse()
	if err != nil {
		log.Fatalf("could not parse options: %v", err)
	}

	if options.UploadFlag {
		uploadS3()
	} else {
		collectFindings()
	}
}
