package teams

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/CMSGov/security-hub-collector/pkg/helpers"
)

// Teams is a struct describing the format we expect in the JSON file
// describing the team mappings
type Teams struct {
	Teams []Team `json:"teams"`
}

// Team is a struct describing a single team and its accounts as we
// expect in the JSON file describing team mappings
type Team struct {
	Name     string    `json:"name"`
	Accounts []Account `json:"accounts"`
}

// Account is a struct describing a single account for a team
type Account struct {
	ID          string `json:"id"`
	Environment string `json:"environment"`
}

// ParseTeamMap takes a path to a team mapping JSON file, reads the file, and returns a Go map of Accounts to team names
func ParseTeamMap(path string) (accountsToTeams map[Account]string, err error) {
	teams, err := readTeamMap(path)
	if err != nil {
		return
	}

	return teams.accountsToTeamNames(), err
}

// readTeamMap - takes the JSON encoded file that maps teams to accounts
// and converts it into a Teams object that we can use later.
func readTeamMap(filePath string) (teams Teams, err error) {
	jsonFile := filepath.Clean(filePath)

	// gosec complains here because we're essentially letting you open
	// any file you want, which if this was a webapp would be pretty
	// sketchy. However, since this is a CLI tool, and you shouldn't be
	// able to open a file you don't have permission for anyway, we can
	// safely ignore its complaints here.
	// #nosec
	f, err := os.Open(jsonFile)
	if err != nil {
		return
	}

	defer func() {
		cerr := f.Close()
		if cerr != nil {
			err = helpers.CombineErrors(err, cerr)
		}
	}()

	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&teams)

	return
}

// accountsToTeamNames returns a map of Accounts to team names
func (t *Teams) accountsToTeamNames() map[Account]string {
	var a = make(map[Account]string)
	for _, team := range t.Teams {
		for _, account := range team.Accounts {
			a[account] = team.Name
		}
	}
	return a
}
