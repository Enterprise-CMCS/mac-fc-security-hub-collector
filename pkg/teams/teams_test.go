package teams

import (
	"reflect"
	"testing"
)

var expectedAccountsToTeams = map[string]string{
	"account 1":  "Test Team 1",
	"account 11": "Test Team 1",
	"account 2":  "Test Team 2",
	"account 22": "Test Team 2",
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
