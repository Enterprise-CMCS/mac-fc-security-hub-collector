package main

import (
	"fmt"

	"github.com/CMSGov/security-hub-collector/internal/aws/client"
	"github.com/CMSGov/security-hub-collector/pkg/securityhubcollector"

	flag "github.com/jessevdk/go-flags"

	"log"
)

// Options describes the command line options available.
type Options struct {
	AssumedRole    string `short:"a" long:"assumedrole" required:"false" description:"Role name to assume when collecting across all accounts."`
	Outfile        string `short:"o" long:"output" required:"false" description:"File to direct output to." default:"SecurityHub-Findings.csv"`
	DefaultProfile string `short:"p" long:"profile" env:"AWS_PROFILE" required:"false" description:"The default AWS profile to use. Overridden if profiles are specified in the team map."`
	Region         string `short:"r" long:"region" env:"AWS_REGION" required:"false" description:"The AWS region to use."`
	S3Bucket       string `short:"s" long:"s3bucket" required:"false" description:"S3 bucket to use to upload results."`
	S3Key          string `short:"k" long:"s3key" required:"false" description:"S3 bucket key, or path, to use to upload results."`
	TeamMapFile    string `short:"m" long:"teammap" required:"true" description:"JSON file containing team to account mappings."`
	UploadFlag     bool   `short:"u" long:"upload-only" description:"Use this flag to upload results to S3"`
}

var options Options

func uploadS3() {
	s3uploader := client.S3Uploader(options.Region, options.DefaultProfile)
	err := securityhubcollector.WriteFindingsToS3(s3uploader, options.S3Bucket, options.S3Key, options.Outfile)
	if err != nil {
		log.Fatalf("could not write output to S3: %v", err)
	}
}

// collectFindings is doing the bulk of our work here; it reads in the
// team map JSON file, builds the HubCollector object, and processes findings
// for each account in the team map.
func collectFindings() {
	teamMap, err := securityhubcollector.ReadTeamMap(options.TeamMapFile)
	if err != nil {
		log.Fatalf("could not parse team map: %v", err)
	}

	profiles := securityhubcollector.BuildProfileList(teamMap)
	acctMap := securityhubcollector.BuildAcctMap(teamMap)

	h := securityhubcollector.HubCollector{
		Outfile: options.Outfile,
		AcctMap: acctMap,
	}

	err = h.WriteHeadersToOutput()
	if err != nil {
		log.Fatalf("could not write headers to output file: %v", err)
	}

	if len(profiles) > 0 {
		for _, profile := range profiles {
			log.Printf("getting findings for profile %v", profile)
			err = h.GetAndWriteFindingsToOutput(options.Region, profile, "")
			if err != nil {
				log.Fatalf("could not get findings for profile %v: %v", profile, err)
			}
		}
	} else if options.AssumedRole != "" {
		for account := range acctMap {
			log.Printf("getting findings for account %v", account)
			roleArn := fmt.Sprintf("arn:aws:iam::%v:role/%v", account, options.AssumedRole)
			h.GetAndWriteFindingsToOutput(options.Region, options.DefaultProfile, roleArn)
			if err != nil {
				log.Fatalf("could not get findings for account %v: %v", account, err)
			}
		}
	} else {
		h.GetAndWriteFindingsToOutput(options.Region, options.DefaultProfile, "")
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
