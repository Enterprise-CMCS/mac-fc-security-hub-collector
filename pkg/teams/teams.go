package teams

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CMSGov/security-hub-collector/pkg/helpers"
)

type duplicateAccountIDError struct {
	message string
}

func (e *duplicateAccountIDError) Error() string {
	return e.message
}

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
		return nil, fmt.Errorf("error parsing team map: %s", err)
	}

	accountsToTeams, err = teams.accountsToTeamNames()
	if err != nil {
		return nil, fmt.Errorf("error parsing team map: %w", err)
	}

	return accountsToTeams, nil
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

// hasAccount checks if the given account ID is in the map of Accounts to team names
func hasAccount(accountsToTeamNames map[Account]string, accountId string) bool {
	for account := range accountsToTeamNames {
		if account.ID == accountId {
			return true
		}
	}
	return false
}

// accountsToTeamNames returns a map of Accounts to team names
func (t *Teams) accountsToTeamNames() (map[Account]string, error) {
	var a = make(map[Account]string)
	for _, team := range t.Teams {
		for _, account := range team.Accounts {
			if hasAccount(a, account.ID) {
				return nil, &duplicateAccountIDError{
					message: fmt.Sprintf("duplicate account ID: %s", account.ID),
				}
			}
			a[account] = team.Name
		}
	}
	return a, nil
}
