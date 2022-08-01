package teams

import "testing"

// This is an example of map that we create from the JSON team map.
var exampleTeamMap = Teams{
	Teams: []Team{
		{
			Name:     "Test Team 1",
			Accounts: []string{"000000000001", "000000000011"},
		},
		{
			Name:     "Test Team 2",
			Accounts: []string{"000000000002", "000000000022"},
		},
	},
}

// This is a helper function to compare two Teams structs and
// make sure they are identical.
func compareTeamMaps(a, b Teams) bool {
	for teamIndex, team := range a.Teams {
		if team.Name != b.Teams[teamIndex].Name {
			return false
		}
		for acctIndex, acct := range team.Accounts {
			if acct != b.Teams[teamIndex].Accounts[acctIndex] {
				return false
			}
		}
	}

	return true
}

func TestReadTeamMap(t *testing.T) {
	extractedTeamMap, err := ReadTeamMap("team_map_test.json")
	if err != nil {
		t.Errorf("ERROR: could not extract team map from test file")
	}

	if !compareTeamMaps(exampleTeamMap, extractedTeamMap) {
		t.Errorf("ERROR: extracted team map does not match expected output")
	}
}
