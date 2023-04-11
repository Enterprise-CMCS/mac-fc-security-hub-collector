package teams

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

var expectedAccountsToTeams = map[Account]string{
	{ID: "account 1", Environment: "dev"}:   "Test Team 1",
	{ID: "account 11", Environment: "test"}: "Test Team 1",
	{ID: "account 2", Environment: "impl"}:  "Test Team 2",
	{ID: "account 22", Environment: "prod"}: "Test Team 2",
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
}
