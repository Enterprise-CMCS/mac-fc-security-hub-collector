package teams

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
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
