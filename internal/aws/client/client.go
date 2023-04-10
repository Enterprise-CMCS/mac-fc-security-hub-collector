package client

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// MakeSecurityHubClient creates a SecurityHub client
func MakeSecurityHubClient(secHubRegion, roleArn string) (*securityhub.Client, error) {
	// if roleArn is provided, this will contain the cross-account credentials provider
	// if not, this will be nil and the default credentials provider chain will be used
	var appCreds aws.CredentialsProvider
	if roleArn != "" {
		stsConfig, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			panic("unable to load SDK config for STS: %s" + err.Error())
		}
		stsClient := sts.NewFromConfig(stsConfig)
		appCreds = stscreds.NewAssumeRoleProvider(stsClient, roleArn)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(secHubRegion), config.WithCredentialsProvider(appCreds))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config for SecurityHub: %s", err)
	}
	client := securityhub.NewFromConfig(cfg)
	return client, nil
}

// MakeS3Uploader creates an S3 upload manager
func MakeS3Uploader(region string) (*manager.Uploader, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config for S3 uploader: %s", err)
	}
	uploader := manager.NewUploader(s3.NewFromConfig(cfg))
	return uploader, nil
}
