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
	Name     string   `json:"name"`
	Accounts []string `json:"accounts"`
	Profiles []string `json:"profiles"`
}

// ParseTeamMap takes a path to a team mapping JSON file, reads the file, and returns Go maps of profiles and accounts to team names
func ParseTeamMap(path string) (profilesToTeams map[string]string, accountsToTeams map[string]string, err error) {
	teams, err := readTeamMap(path)
	if err != nil {
		return
	}

	return teams.profilesToTeamNames(), teams.accountsToTeamNames(), err
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
			err = helpers.CombineErrors([]error{err, cerr})
		}
	}()

	err = json.NewDecoder(f).Decode(&teams)

	return
}

// accountsToTeamNames returns a map of accounts to team names
func (t *Teams) accountsToTeamNames() map[string]string {
	var a = make(map[string]string)
	for _, team := range t.Teams {
		for _, account := range team.Accounts {
			a[account] = team.Name
		}
	}
	return a
}

// profilesToTeamNames returns a map of profiles to team names
func (t *Teams) profilesToTeamNames() map[string]string {
	var p = make(map[string]string)
	for _, team := range t.Teams {
		for _, profile := range team.Profiles {
			p[profile] = team.Name
		}
	}
	return p
}