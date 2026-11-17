package teams

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var expectedAccountsToTeams = map[Account]string{
	{ID: "account 1", Environment: "dev", RoleARN: "arn:aws:iam::000000000011:role/CustomRole"}:   "Test Team 1",
	{ID: "account 11", Environment: "test", RoleARN: "arn:aws:iam::000000000012:role/CustomRole"}: "Test Team 1",
	{ID: "account 2", Environment: "impl", RoleARN: "arn:aws:iam::000000000013:role/CustomRole"}:  "Test Team 2",
	{ID: "account 22", Environment: "prod", RoleARN: "arn:aws:iam::000000000014:role/CustomRole"}: "Test Team 2",
}

// take a path to a test JSON file and encode it to a base64 string
func base64EncodeTestJSON(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to valid JSON file: %s", err)
	}
	defer file.Close()
	fileContents, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %s", err)
	}
	return base64.StdEncoding.EncodeToString(fileContents), nil
}

// this test checks if the team map is parsed correctly for a valid team map. it first converts the valid JSON to the expected base64 encoded string
func TestParseTeamMap(t *testing.T) {
	validStr, err := base64EncodeTestJSON("team_map_test_valid.json")
	if err != nil {
		t.Errorf("failed to read valid JSON file: %s", err)
	}
	actualAccountsToTeams, err := ParseTeamMap(validStr)
	if err != nil {
		t.Errorf("ERROR: could not extract team map from test string: %s", err)
	}
	if !reflect.DeepEqual(expectedAccountsToTeams, actualAccountsToTeams) {
		t.Errorf("ERROR: expected account to team map does not match actual. Expected: %#v, Actual: %#v", expectedAccountsToTeams, actualAccountsToTeams)
	}

	// this test checks that a duplicate account ID is caught
	duplicateStr, err := base64EncodeTestJSON("team_map_test_duplicate.json")
	if err != nil {
		t.Errorf("failed to read duplicate JSON file: %s", err)
	}
	_, err = ParseTeamMap(duplicateStr)
	var duplicateAccountIDError *duplicateAccountIDError
	if err == nil || !errors.As(err, &duplicateAccountIDError) {
		t.Error("ERROR: didn't get expected error for duplicate account ID", err)
	}

	// Test invalid ARN
	invalidStr, err := base64EncodeTestJSON("team_map_test_invalid_arn.json")
	if err != nil {
		t.Errorf("failed to read invalid JSON file: %s", err)
	}
	_, err = ParseTeamMap(invalidStr)
	var invalidRoleARNError *invalidRoleARNError
	if err == nil || !errors.As(err, &invalidRoleARNError) {
		t.Error("ERROR: didn't get expected error for invalid Role ARN", err)
	}
}

func TestGetTeamsFromTeamsAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/team/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("unexpected Authorization header: %s", got)
		}
		fmt.Fprint(w, `[
			{"name": "Team 1", "aws_accounts": [
				{"id": "000000000011", "name": "dev", "is_inactive": false},
				{"id": "000000000012", "name": "prod", "is_inactive": true}
			]},
			{"name": "Team 2", "aws_accounts": [
				{"id": "000000000013", "name": "dev", "is_inactive": false},
				{"id": "360433083926", "name": "seatool", "is_inactive": false}
			]}
		]`)
	}))
	defer server.Close()

	got, err := GetTeamsFromTeamsAPI(server.URL, "test-key", "CustomRole")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	want := map[Account]string{
		{ID: "000000000011", Environment: "dev", RoleARN: "arn:aws:iam::000000000011:role/CustomRole"}: "Team 1",
		{ID: "000000000013", Environment: "dev", RoleARN: "arn:aws:iam::000000000013:role/CustomRole"}: "Team 2",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("accounts to teams mismatch (-want +got):\n%s", diff)
	}
}

func TestGetTeamsFromTeamsAPIErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	if _, err := GetTeamsFromTeamsAPI(server.URL, "test-key", "CustomRole"); err == nil {
		t.Error("expected an error for HTTP 403")
	}
}
