package teams

import (
	"fmt"
	"slices"

	"github.com/Enterprise-CMCS/mac-fc-macbis-cost-analysis/pkg/athenalib"
	"github.com/aws/aws-sdk-go/aws/session"
)

// SEATool accounts are in the Athena team data (because we get CUR data from them)
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

type Account struct {
	ID          string `json:"id"`          // AWS Account ID
	Environment string `json:"environment"` // Environment (using account alias from Athena)
}

func GetTeamsFromAthena(sess *session.Session, teamsTable, queryOutputLocation string) (map[Account]string, error) {
	// Load account information from Athena
	accounts, err := athenalib.LoadTeams(sess, teamsTable, queryOutputLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to load teams from Athena: %w", err)
	}

	// Convert the Athena results into our account map format
	accountsToTeams := make(map[Account]string)

	for _, acct := range accounts {
		// skip inactive accounts
		if acct.IsInactive {
			continue
		}

		// skip SEATool accounts
		if slices.Contains(seaToolAccountIDs, acct.AWSAccountID) {
			continue
		}

		// Check for duplicate account IDs
		if hasAccount(accountsToTeams, acct.AWSAccountID) {
			return nil, &duplicateAccountIDError{
				message: fmt.Sprintf("duplicate account ID in Athena team data: %s", acct.AWSAccountID),
			}
		}

		account := Account{
			ID:          acct.AWSAccountID,
			Environment: acct.Alias, // Use the alias as the environment value for compatibility with existing QuickSight dashboard
		}

		accountsToTeams[account] = acct.Team
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
