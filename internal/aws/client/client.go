package client

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// functions in this library panic on error to simplify error handling

// SecurityHub creates a SecurityHub client using the credentials provider chain. Optionally configures cross-account credentials given a role to assume
func SecurityHub(secHubRegion, roleArn string) *securityhub.Client {
	// if roleArn is provided, this will contain the cross-account credentials provider
	// if not, this will be nil and the default credentials provider chain will be used
	var appCreds aws.CredentialsProvider
	if roleArn != "" {
		stsConfig, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			panic("unable to load SDK config for STS, " + err.Error())
		}
		stsClient := sts.NewFromConfig(stsConfig)
		appCreds = stscreds.NewAssumeRoleProvider(stsClient, roleArn)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(secHubRegion), config.WithCredentialsProvider(appCreds))
	if err != nil {
		panic("unable to load SDK config for SecurityHub, " + err.Error())
	}
	client := securityhub.NewFromConfig(cfg)
	return client
}

// S3Uploader creates an S3 upload manager
func S3Uploader(region string) *manager.Uploader {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		panic("unable to load SDK config, " + err.Error())
	}
	uploader := manager.NewUploader(s3.NewFromConfig(cfg))
	return uploader
}
