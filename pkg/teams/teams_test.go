package teams

import (
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
	actualAccountsToTeams, err := ParseTeamMap("team_map_test.json")
	if err != nil {
		t.Errorf("ERROR: could not extract team map from test file: %s", err)
	}

	if !reflect.DeepEqual(expectedAccountsToTeams, actualAccountsToTeams) {
		t.Errorf("ERROR: expected account to team map does not match actual. Expected: %#v, Actual: %#v", expectedAccountsToTeams, actualAccountsToTeams)
	}
}
