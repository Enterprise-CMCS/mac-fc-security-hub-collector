package main

import (
	"github.com/CMSGov/security-hub-collector/internal/aws/session"
	"github.com/CMSGov/security-hub-collector/pkg/securityhubcollector"

	"github.com/aws/aws-sdk-go/service/securityhub"
	flag "github.com/jessevdk/go-flags"
	"go.uber.org/zap"

	"log"
)

// Options describes the command line options available.
type Options struct {
	Outfile     string `short:"o" long:"output" required:"false" description:"File to direct output to." default:"SecurityHub-Findings.csv"`
	Profile     string `short:"p" long:"profile" env:"AWS_PROFILE" required:"false" description:"The AWS profile to use."`
	Region      string `short:"r" long:"region" env:"AWS_REGION" required:"false" description:"The AWS region to use."`
	TeamMapFile string `short:"m" long:"teammap" required:"true" description:"JSON file containing team to account mappings."`
}

var options Options
var logger *zap.Logger

// makeHubClient establishes our session with AWS.
func makeHubClient(region, profile string) *securityhub.SecurityHub {
	sess := session.MustMakeSession(region, profile)
	hubClient := securityhub.New(sess)
	return hubClient
}

// collectFindings is doing the bulk of our work here; it reads in the
// team map JSON file, builds the HubCollector object, gets the findings,
// and then writes the findings to the output file.
func collectFindings() {
	teamMap, err := securityhubcollector.ReadTeamMap(options.TeamMapFile)
	if err != nil {
		log.Fatalf("could not parse team map: %v", err)
	}

	profiles := securityhubcollector.BuildProfileList(teamMap)
	acctMap := securityhubcollector.BuildAcctMap(teamMap)

	if len(profiles) > 0 {
		for idx, profile := range profiles {
			log.Printf("%v: %v", idx, profile)
			processFindings(idx, acctMap, profile)
		}
	} else {
		processFindings(0, acctMap, options.Profile)
	}
}

func processFindings(index int, acctMap map[string]string, profile string) {
	h := securityhubcollector.HubCollector{
		Logger:    logger,
		HubClient: makeHubClient(options.Region, profile),
		Outfile:   options.Outfile,
		AcctMap:   acctMap,
	}

	findingsList, err := h.GetSecurityHubFindings()
	if err != nil {
		log.Fatalf("could not get security hub findings: %v", err)
	}
	writeHeaders := true
	if index > 0 {
		writeHeaders = false
	}

	err = h.WriteFindingsToOutput(findingsList, writeHeaders)
	if err != nil {
		log.Fatalf("could not write outputfile: %v", err)
	}
}

func main() {
	// Parse out command line options:
	parser := flag.NewParser(&options, flag.Default)
	_, err := parser.Parse()
	if err != nil {
		log.Fatalf("could not parse options: %v", err)
	}

	// Initialize the logger:
	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("could not intialize logger: %v", err)
	}

	collectFindings()
}
