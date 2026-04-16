package teams

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	teamsapi "github.com/Enterprise-CMCS/mac-fc-teams-api/client"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// SEATool accounts are in the Teams API team data (because we get CUR data from them)
// but not in the MACBIS OU, so our cloud rule doesn't push the cross account role to them
var seaToolAccountIDs = []string{
	"360433083926",
	"204488982178",
	"635526538414",
}

type duplicateAccountIDError struct {
	message string
}

func (e *duplicateAccountIDError) Error() string {
	return e.message
}

type invalidRoleARNError struct {
	message string
}

func (e *invalidRoleARNError) Error() string {
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

type Account struct {
	ID          string
	Environment string
	RoleARN     string
}

// ParseTeamMap takes a base64 encoded team map string and returns a Go map of Accounts to team names
func ParseTeamMap(base64Str string) (accountsToTeams map[Account]string, err error) {
	var teams Teams
	b, err := base64.URLEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding team map: %s", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&teams)
	if err != nil {
		return nil, fmt.Errorf("error JSON decoding team map: %s", err)
	}

	accountsToTeams, err = teams.accountsToTeamNames()
	if err != nil {
		return nil, fmt.Errorf("error parsing team map: %w", err)
	}

	return accountsToTeams, nil
}

// GetTeamsFromTeamsAPI loads a map of Accounts to team names from the Teams API
func GetTeamsFromTeamsAPI(baseURL string, apiKey string, rolePath string) (map[Account]string, error) {
	client := teamsapi.NewClient(baseURL, apiKey)

	teams, err := client.GetAllTeams()
	if err != nil {
		return nil, fmt.Errorf("failed to load teams from Teams API: %w", err)
	}

	accountsToTeams := make(map[Account]string)

	for _, team := range teams {
		for _, acct := range team.AWSAccounts {
			// skip inactive accounts
			if acct.IsInactive {
				continue
			}

			// skip SEATool accounts
			if slices.Contains(seaToolAccountIDs, acct.ID) {
				continue
			}

			// check for duplicate account IDs
			if hasAccount(accountsToTeams, acct.ID) {
				return nil, &duplicateAccountIDError{
					message: fmt.Sprintf("duplicate account ID in Teams API data: %s", acct.ID),
				}
			}

			account := Account{
				ID:          acct.ID,
				Environment: acct.Name, // Use the name as the environment value for compatibility with existing QuickSight dashboard
				RoleARN:     fmt.Sprintf("arn:aws:iam::%s:role/%s", acct.ID, rolePath),
			}

			accountsToTeams[account] = team.Name
		}
	}

	return accountsToTeams, nil
}

// hasAccount checks if the given account ID is in the map of Accounts to team names
func hasAccount(accountsToTeamNames map[Account]string, accountID string) bool {
	for account := range accountsToTeamNames {
		if account.ID == accountID {
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

			if !arn.IsARN(account.RoleARN) {
				return nil, &invalidRoleARNError{
					message: fmt.Sprintf("invalid role ARN for account %s: %s Input must be a valid Role ARN", account.ID, account.RoleARN),
				}
			}
			a[account] = team.Name
		}
	}
	return a, nil
}
