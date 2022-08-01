package teams

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// ReadTeamMap - takes the JSON encoded file that maps teams to accounts
// and converts it into a Teams object that we can use later.
func ReadTeamMap(filePath string) (teams Teams, err error) {
	jsonFile := filepath.Clean(filePath)

	// gosec complains here because we're essentially letting you open
	// any file you want, which if this was a webapp would be pretty
	// sketchy. However, since this is a CLI tool, and you shouldn't be
	// able to open a file you don't have permission for anyway, we can
	// safely ignore its complaints here.
	// #nosec
	f, err := os.Open(jsonFile)

	defer func() {
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
	}()

	err = json.NewDecoder(f).Decode(&teams)

	return
}

// AccountsToTeamNames returns a map of accounts to team names
func (t *Teams) AccountsToTeamNames() map[string]string {
	var a = make(map[string]string)
	for _, team := range t.Teams {
		for _, account := range team.Accounts {
			a[account] = team.Name
		}
	}
	return a
}

// ProfilesToTeamNames returns a map of profiles to team names
func (t *Teams) ProfilesToTeamNames() map[string]string {
	var p = make(map[string]string)
	for _, team := range t.Teams {
		for _, profile := range team.Profiles {
			p[profile] = team.Name
		}
	}
	return p
}
