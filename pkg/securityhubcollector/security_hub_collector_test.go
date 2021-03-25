package securityhubcollector

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"
)

type mockSecurityHubClient struct {
	securityhubiface.SecurityHubAPI
}

var activeSecurityFinding = &securityhub.AwsSecurityFinding{
	AwsAccountId: aws.String("000000000001"),
	CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
	Description:  aws.String("Active Test Finding"),
	ProductArn:   aws.String("This is a test ProductArn"),
	RecordState:  aws.String("ACTIVE"),
	Resources: []*aws.Resource{
		{Id: aws.String("fake-id-001"), Type: aws.String("fake-type-001")},
	},
	SchemaVersion: aws.String("This is a fake schema version"),
	Title:         aws.String("Test Finding Title"),
	UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
	Workflow:      *Workflow{Status: aws.String("NEW")},
}

var resolvedSecurityFinding = &securityhub.AwsSecurityFinding{
	AwsAccountId: aws.String("000000000001"),
	CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
	Description:  aws.String("Resolved Test Finding"),
	ProductArn:   aws.String("This is a test ProductArn"),
	RecordState:  aws.String("ACTIVE"),
	Resources: []*aws.Resource{
		{Id: aws.String("fake-id-002"), Type: aws.String("fake-type-002")},
	},
	SchemaVersion: aws.String("This is a fake schema version"),
	Title:         aws.String("Test Finding Title"),
	UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
	Workflow:      *Workflow{Status: aws.String("RESOLVED")},
}

var archivedSecurityFinding = &securityhub.AwsSecurityFinding{
	AwsAccountId: aws.String("000000000001"),
	CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
	Description:  aws.String("Resolved Test Finding"),
	ProductArn:   aws.String("This is a test ProductArn"),
	RecordState:  aws.String("ARCHIVED"),
	Resources: []*aws.Resource{
		{Id: aws.String("fake-id-003"), Type: aws.String("fake-type-003")},
	},
	SchemaVersion: aws.String("This is a fake schema version"),
	Title:         aws.String("Test Finding Title"),
	UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
	Workflow:      *Workflow{Status: aws.String("NEW")},
}
