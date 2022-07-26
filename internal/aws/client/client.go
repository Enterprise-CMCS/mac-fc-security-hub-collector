package client

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/securityhub"
)

// MakeSession creates an AWS Session, with appropriate defaults,
// using shared credentials, and with region and profile overrides.
func makeSession(region, profile string) (*session.Session, error) {
	sessOpts := session.Options{
		SharedConfigState:       session.SharedConfigEnable,
		AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
	}
	if profile != "" {
		sessOpts.Profile = profile
	}
	if region != "" {
		sessOpts.Config = aws.Config{
			Region: aws.String(region),
		}
	}
	return session.NewSessionWithOptions(sessOpts)
}

// MustMakeSession creates an AWS Session using MakeSession and ensures
// that it is valid.
func mustMakeSession(region, profile string) *session.Session {
	return session.Must(makeSession(region, profile))
}

// SecurityHub establishes our session with AWS and creates SecurityHub connection
func SecurityHub(region, profile string, roleArn string) *securityhub.SecurityHub {
	sess := mustMakeSession(region, profile)
	if roleArn != "" {
		log.Printf("%v", roleArn)
		creds := stscreds.NewCredentials(sess, roleArn)
		hubClient := securityhub.New(sess, aws.NewConfig().WithCredentials(creds).WithMaxRetries(10))
		return hubClient
	}
	hubClient := securityhub.New(sess)
	return hubClient
}

// S3Uploader establishes our session with AWS and creates S3 connection
func S3Uploader(region, profile string) *s3manager.Uploader {
	sess := mustMakeSession(region, profile)
	s3Uploader := s3manager.NewUploader(sess)
	return s3Uploader
}
