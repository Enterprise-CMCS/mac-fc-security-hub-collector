package securityhubcollector

import (
	"log"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/benbjohnson/clock"
	"github.com/google/go-cmp/cmp"
)

func mustParseTime(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		log.Fatalf("Error parsing time %q: %s", s, err)
	}
	return t
}

type testCase struct {
	name        string
	teamName    string
	environment string
	finding     types.AwsSecurityFinding
	expected    [][]string
}

// This function tests the conversion of a security finding into the
// slice format we expect for writing out our CSV.
func TestConvertFindingToRows(t *testing.T) {
	testCases := []testCase{
		{
			name:        "Active finding, single resource",
			teamName:    "Test Team 1",
			environment: "dev",
			finding: types.AwsSecurityFinding{
				AwsAccountId: aws.String("000000000001"),
				CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
				Description:  aws.String("Active Test Finding"),
				ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/securityhub"),
				ProductName:  aws.String("Security Hub"),
				RecordState:  types.RecordStateActive,
				Resources: []types.Resource{
					{
						Id:     aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000001"),
						Type:   aws.String("AwsEc2Vpc"),
						Region: aws.String("us-east-1"),
					},
				},
				SchemaVersion: aws.String("2018-10-08"),
				Title:         aws.String("Active Test Finding Title"),
				UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
				Workflow:      &types.Workflow{Status: types.WorkflowStatusNew},
				Severity:      &types.Severity{Label: types.SeverityLabelHigh},
				Remediation: &types.Remediation{
					Recommendation: &types.Recommendation{
						Text: aws.String("Do the thing"),
						Url:  aws.String("https://example.com/dothething"),
					},
				},
				Compliance: &types.Compliance{Status: types.ComplianceStatusFailed},
			},
			expected: [][]string{
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
					"us-east-1",
					"dev",
					"Security Hub",
					"01-01-2023",
				},
			},
		},

		{
			name:        "Active finding, multiple resources",
			teamName:    "Test Team 1",
			environment: "impl",
			finding: types.AwsSecurityFinding{
				AwsAccountId: aws.String("000000000001"),
				CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
				Description:  aws.String("MultiResource Test Finding"),
				ProductArn:   aws.String("arn:aws:securityhub:us-west-2::product/aws/securityhub"),
				ProductName:  aws.String("Security Hub"),
				RecordState:  types.RecordStateActive,
				Resources: []types.Resource{
					{
						Id:     aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000002"),
						Type:   aws.String("AwsEc2Vpc"),
						Region: aws.String("us-west-2"),
					},
					{
						Id:     aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000003"),
						Type:   aws.String("AwsEc2Vpc"),
						Region: aws.String("us-west-2"),
					},
				},
				SchemaVersion: aws.String("2018-10-08"),
				Title:         aws.String("MultiResource Test Finding Title"),
				UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
				Workflow:      &types.Workflow{Status: types.WorkflowStatusNew},
				Severity:      &types.Severity{Label: types.SeverityLabelHigh},
				Remediation: &types.Remediation{
					Recommendation: &types.Recommendation{
						Text: aws.String("Do the thing"),
						Url:  aws.String("https://example.com/dothething"),
					},
				},
				Compliance: &types.Compliance{Status: types.ComplianceStatusFailed},
			},
			expected: [][]string{
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
					"us-west-2",
					"impl",
					"Security Hub",
					"01-01-2023",
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
					"us-west-2",
					"impl",
					"Security Hub",
					"01-01-2023",
				},
			},
		},

		{
			name:        "Active finding, no compliance information",
			teamName:    "Test Team 1",
			environment: "prod",
			finding: types.AwsSecurityFinding{
				AwsAccountId: aws.String("000000000001"),
				CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
				Description:  aws.String("Active Test Finding"),
				ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/securityhub"),
				ProductName:  aws.String("Security Hub"),
				RecordState:  types.RecordStateActive,
				Resources: []types.Resource{
					{
						Id:     aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000001"),
						Type:   aws.String("AwsEc2Vpc"),
						Region: aws.String("us-east-1"),
					},
				},
				SchemaVersion: aws.String("2018-10-08"),
				Title:         aws.String("Active Test Finding Title"),
				UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
				Workflow:      &types.Workflow{Status: types.WorkflowStatusNew},
				Severity:      &types.Severity{Label: types.SeverityLabelHigh},
				Remediation: &types.Remediation{
					Recommendation: &types.Recommendation{
						Text: aws.String("Do the thing"),
						Url:  aws.String("https://example.com/dothething"),
					},
				},
				Compliance: nil,
			},
			expected: [][]string{
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
					"us-east-1",
					"prod",
					"Security Hub",
					"01-01-2023",
				},
			},
		},

		{
			name:        "Suppressed finding",
			teamName:    "Test Team 1",
			environment: "dev",
			finding: types.AwsSecurityFinding{
				AwsAccountId: aws.String("000000000001"),
				CreatedAt:    aws.String("2020-03-22T13:22:13.933Z"),
				Description:  aws.String("Suppressed Test Finding"),
				ProductArn:   aws.String("arn:aws:securityhub:us-east-1::product/aws/securityhub"),
				ProductName:  aws.String("Security Hub"),
				RecordState:  types.RecordStateActive,
				Resources: []types.Resource{
					{
						Id:     aws.String("arn:aws:ec2:us-test-1:000000000001:vpc/vpc-00000000000000001"),
						Type:   aws.String("AwsEc2Vpc"),
						Region: aws.String("us-east-1"),
					},
				},
				SchemaVersion: aws.String("2018-10-08"),
				Title:         aws.String("Suppressed Test Finding Title"),
				UpdatedAt:     aws.String("2020-03-22T13:22:13.933Z"),
				Workflow:      &types.Workflow{Status: types.WorkflowStatusSuppressed},
				Severity:      &types.Severity{Label: types.SeverityLabelHigh},
				Remediation: &types.Remediation{
					Recommendation: &types.Recommendation{
						Text: aws.String("Do the thing"),
						Url:  aws.String("https://example.com/dothething"),
					},
				},
				Compliance: &types.Compliance{Status: types.ComplianceStatusFailed},
			},
			expected: [][]string{
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
					"us-east-1",
					"dev",
					"Security Hub",
					"01-01-2023",
				},
			},
		},
	}

	h := HubCollector{}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClock := clock.NewMock()
			mockClock.Set(mustParseTime("2023-01-01"))

			actual := h.convertFindingToRows(tc.finding, tc.teamName, tc.environment, mockClock)
			if diff := cmp.Diff(tc.expected, actual); diff != "" {
				t.Fatalf("Expected rows did not match actual: %s", diff)
			}
		})
	}
}
