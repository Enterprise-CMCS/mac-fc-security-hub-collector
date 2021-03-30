package securityhubcollector

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"

	"go.uber.org/zap"
)

type mockSecurityHubClient struct {
	securityhubiface.SecurityHubAPI
}

var logger, _ = zap.NewProduction()

// This is an active security finding that is the most basic that we're
// likely to see from Security Hub and is a type we want to actually see.
var activeSecurityFinding = &securityhub.AwsSecurityFinding{
	AwsAccountId: aws.String("000000000001"),
	CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
	Description:  aws.String("Active Test Finding"),
	ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/securityhub"),
	RecordState:  aws.String("ACTIVE"),
	Resources: []*securityhub.Resource{
		{
			Id:   aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000001"),
			Type: aws.String("AwsEc2Vpc"),
		},
	},
	SchemaVersion: aws.String("2018-10-08"),
	Title:         aws.String("Active Test Finding Title"),
	UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
	Workflow:      &securityhub.Workflow{Status: aws.String("NEW")},
	Severity:      &securityhub.Severity{Label: aws.String("HIGH")},
	Remediation: &securityhub.Remediation{
		Recommendation: &securityhub.Recommendation{
			Text: aws.String("Do the thing"),
			Url:  aws.String("https://example.com/dothething"),
		},
	},
	Compliance: &securityhub.Compliance{Status: aws.String("FAILED")},
}

// This is a valid finding with multiple resources in the same finding
// for testing that functionality.
var multiResourceSecurityFinding = &securityhub.AwsSecurityFinding{
	AwsAccountId: aws.String("000000000001"),
	CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
	Description:  aws.String("MultiResource Test Finding"),
	ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/securityhub"),
	RecordState:  aws.String("ACTIVE"),
	Resources: []*securityhub.Resource{
		{
			Id:   aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000002"),
			Type: aws.String("AwsEc2Vpc"),
		},
		{
			Id:   aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000003"),
			Type: aws.String("AwsEc2Vpc"),
		},
	},
	SchemaVersion: aws.String("2018-10-08"),
	Title:         aws.String("MultiResource Test Finding Title"),
	UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
	Workflow:      &securityhub.Workflow{Status: aws.String("NEW")},
	Severity:      &securityhub.Severity{Label: aws.String("HIGH")},
	Remediation: &securityhub.Remediation{
		Recommendation: &securityhub.Recommendation{
			Text: aws.String("Do the thing"),
			Url:  aws.String("https://example.com/dothething"),
		},
	},
	Compliance: &securityhub.Compliance{Status: aws.String("FAILED")},
}

// This is a helper function to create a new HubCollector object; we're
// doing this so creating a new HubCollector object is easy in tests.
func testHubCollector(hubclient securityhubiface.SecurityHubAPI) HubCollector {
	output := HubCollector{
		Logger:    logger,
		HubClient: hubclient,
		Outfile:   "test-output.csv",
	}

	return output
}

// We have to make our own function to test whether our expected outputs
// are equal.
func outputEqual(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		for e, x := range v {
			if x != b[i][e] {
				return false
			}
		}
	}
	return true
}

func TestConvertFindingToRows(t *testing.T) {
	activeExpect := [][]string{
		{
			"Team TBD",
			"AwsEc2Vpc",
			"Active Test Finding Title",
			"Active Test Finding",
			"HIGH",
			"Do the thing",
			"https://example.com/dothething",
			"arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000001",
			"000000000001",
			"FAILED",
			"ACTIVE",
		},
	}

	multiResourceExpect := [][]string{
		{
			"Team TBD",
			"AwsEc2Vpc",
			"MultiResource Test Finding Title",
			"MultiResource Test Finding",
			"HIGH",
			"Do the thing",
			"https://example.com/dothething",
			"arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000002",
			"000000000001",
			"FAILED",
			"ACTIVE",
		},
		{
			"Team TBD",
			"AwsEc2Vpc",
			"MultiResource Test Finding Title",
			"MultiResource Test Finding",
			"HIGH",
			"Do the thing",
			"https://example.com/dothething",
			"arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000003",
			"000000000001",
			"FAILED",
			"ACTIVE",
		},
	}

	h := testHubCollector(&mockSecurityHubClient{})

	if !outputEqual(h.ConvertFindingToRows(activeSecurityFinding), activeExpect) {
		t.Errorf("ERROR: Active finding conversion does not match expectations")
	}

	if !outputEqual(h.ConvertFindingToRows(multiResourceSecurityFinding), multiResourceExpect) {
		t.Errorf("ERROR: MultiResource finding conversion does not match expectations")
	}

}
