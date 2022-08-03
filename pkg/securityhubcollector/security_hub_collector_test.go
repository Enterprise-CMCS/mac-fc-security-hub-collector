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

// This is an active security finding that is the most basic that we're
// likely to see from Security Hub and is a type we want to actually see.
var noComplianceSecurityFinding = &securityhub.AwsSecurityFinding{
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
	Compliance: nil,
}

// This is an active security finding that is the most basic that we're
// likely to see from Security Hub and is a type we want to actually see.
var suppressedSecurityFinding = &securityhub.AwsSecurityFinding{
	AwsAccountId: aws.String("000000000001"),
	CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
	Description:  aws.String("Suppressed Test Finding"),
	ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/securityhub"),
	RecordState:  aws.String("ACTIVE"),
	Resources: []*securityhub.Resource{
		{
			Id:   aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000001"),
			Type: aws.String("AwsEc2Vpc"),
		},
	},
	SchemaVersion: aws.String("2018-10-08"),
	Title:         aws.String("Suppressed Test Finding Title"),
	UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
	Workflow:      &securityhub.Workflow{Status: aws.String("SUPPRESSED")},
	Severity:      &securityhub.Severity{Label: aws.String("HIGH")},
	Remediation: &securityhub.Remediation{
		Recommendation: &securityhub.Recommendation{
			Text: aws.String("Do the thing"),
			Url:  aws.String("https://example.com/dothething"),
		},
	},
	Compliance: &securityhub.Compliance{Status: aws.String("FAILED")},
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

// This function tests the conversion of a security finding into the
// slice format we expect for writing out our CSV.
func TestConvertFindingToRows(t *testing.T) {
	activeExpect := [][]string{
		{
			"Test Team 1",
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
			"NEW",
			"2020-03-22T13:22:13.933Z",
			"2020-03-22T13:22:13.933Z",
		},
	}

	multiResourceExpect := [][]string{
		{
			"Test Team 1",
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
			"NEW",
			"2020-03-22T13:22:13.933Z",
			"2020-03-22T13:22:13.933Z",
		},
		{
			"Test Team 1",
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
			"NEW",
			"2020-03-22T13:22:13.933Z",
			"2020-03-22T13:22:13.933Z",
		},
	}

	noComplianceExpect := [][]string{
		{
			"Test Team 1",
			"AwsEc2Vpc",
			"Active Test Finding Title",
			"Active Test Finding",
			"HIGH",
			"Do the thing",
			"https://example.com/dothething",
			"arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000001",
			"000000000001",
			"",
			"ACTIVE",
			"NEW",
			"2020-03-22T13:22:13.933Z",
			"2020-03-22T13:22:13.933Z",
		},
	}

	suppressedExpect := [][]string{
		{
			"Test Team 1",
			"AwsEc2Vpc",
			"Suppressed Test Finding Title",
			"Suppressed Test Finding",
			"HIGH",
			"Do the thing",
			"https://example.com/dothething",
			"arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000001",
			"000000000001",
			"FAILED",
			"ACTIVE",
			"SUPPRESSED",
			"2020-03-22T13:22:13.933Z",
			"2020-03-22T13:22:13.933Z",
		},
	}

	h := HubCollector{}
	teamName := "Test Team 1"

	if !outputEqual(h.convertFindingToRows(activeSecurityFinding, teamName), activeExpect) {
		t.Errorf("ERROR: Active finding conversion does not match expectations")
	}

	if !outputEqual(h.convertFindingToRows(multiResourceSecurityFinding, teamName), multiResourceExpect) {
		t.Errorf("ERROR: MultiResource finding conversion does not match expectations")
	}

	if !outputEqual(h.convertFindingToRows(noComplianceSecurityFinding, teamName), noComplianceExpect) {
		t.Errorf("ERROR: NoCompliance finding conversion does not match expectations")
	}

	if !outputEqual(h.convertFindingToRows(suppressedSecurityFinding, teamName), suppressedExpect) {
		t.Errorf("ERROR: Suppressed finding conversion does not match expectations")
	}

}
