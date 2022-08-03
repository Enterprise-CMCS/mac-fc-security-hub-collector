package helpers

import (
	"fmt"
	"strings"
)

// CombineErrors combines the messages from multiple errors into a single error. It returns nil if all errors are nil.
func CombineErrors(errs []error) error {
	var errStrs []string
	var foundErr bool
	for _, err := range errs {
		if err != nil {
			foundErr = true
			errStrs = append(errStrs, err.Error())
		}
	}
	if foundErr {
		return fmt.Errorf(strings.Join(errStrs, "; "))
	}
	return nil
}
