package helpers

import (
	"fmt"
	"testing"
)

type HelpersTestCase struct {
	errors        []error
	expectedError error
}

var error1 = fmt.Errorf("error1")
var error2 = fmt.Errorf("error2")
var error3 = fmt.Errorf("error3")

var HelpersTestCases = []HelpersTestCase{
	{
		errors: []error{
			nil,
			nil,
			nil,
		},
		expectedError: nil,
	},
	{
		errors: []error{
			error1,
			error2,
			error3,
		},
		expectedError: fmt.Errorf("error1; error2; error3"),
	},
	{
		errors: []error{
			nil,
			error2,
			nil,
		},
		expectedError: fmt.Errorf("error2"),
	},
	{
		errors: []error{
			error1,
			nil,
			error3,
		},
		expectedError: fmt.Errorf("error1; error3"),
	},
}

// sameError returns true if errors are both nil or have the same error string.
// it should only be used for testing purposes
func sameError(x, y error) bool {
	if x == nil || y == nil {
		return x == nil && y == nil
	}
	return x.Error() == y.Error()
}

func TestCombineErrors(t *testing.T) {
	for _, testCase := range HelpersTestCases {
		actualError := CombineErrors(testCase.errors)
		if !sameError(testCase.expectedError, actualError) {
			t.Errorf("ERROR: expected error does not match actual error. Expected: %v, Actual: %v", testCase.expectedError, actualError)
		}
	}
}
