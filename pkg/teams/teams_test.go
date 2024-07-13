package teams

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var expectedAccountsToTeams = map[Account]string{
	{ID: "account 1", Environment: "dev", RoleARN: "arn:aws:iam::000000000011:role/CustomRole"}:   "Test Team 1",
	{ID: "account 11", Environment: "test", RoleARN: "arn:aws:iam::000000000012:role/CustomRole"}: "Test Team 1",
	{ID: "account 2", Environment: "impl", RoleARN: "arn:aws:iam::000000000013:role/CustomRole"}:  "Test Team 2",
	{ID: "account 22", Environment: "prod", RoleARN: "arn:aws:iam::000000000014:role/CustomRole"}: "Test Team 2",
}

func TestParseTeamMap(t *testing.T) {
	// this test checks if the team map is parsed correctly for a valid team map
	actualAccountsToTeams, err := ParseTeamMap("team_map_test_valid.json")
	if err != nil {
		t.Errorf("ERROR: could not extract team map from test file: %s", err)
	}
	if !reflect.DeepEqual(expectedAccountsToTeams, actualAccountsToTeams) {
		t.Errorf("ERROR: expected account to team map does not match actual. Expected: %#v, Actual: %#v", expectedAccountsToTeams, actualAccountsToTeams)
	}

	// this test checks that a duplicate account ID is caught
	_, err = ParseTeamMap("team_map_test_duplicate.json")
	fmt.Printf("err: %v", err)
	var duplicateAccountIDError *duplicateAccountIDError
	if err == nil || !errors.As(err, &duplicateAccountIDError) {
		t.Error("ERROR: didn't get expected error for duplicate account ID", err)
	}

	// Test invalid ARN
	_, err = ParseTeamMap("team_map_test_invalid_arn.json")
	if err == nil {
		t.Error("ERROR: expected error for invalid ARN, but got nil")
	} else if !strings.Contains(err.Error(), "invalid role ARN for account") {
		t.Errorf("ERROR: unexpected error message for invalid ARN: %s", err)
	}
}
