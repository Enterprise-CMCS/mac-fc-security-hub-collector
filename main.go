package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// version is the published version of the utility
var version string

const (
	// VerboseFlag is the Verbose Flag
	VerboseFlag string = "verbose"
)

// initFlags is where command line flags are instantiated
func initFlags(flag *pflag.FlagSet) {

	// Verbose
	flag.BoolP(VerboseFlag, "v", false, "log messages at the debug level.")

	flag.SortFlags = false
}

// checkConfig is how the input to command line flags are checked
func checkConfig(v *viper.Viper) error {

	return nil
}

func main() {
	root := cobra.Command{
		Use:   "my-cli-tool [flags]",
		Short: "My CLI Tool",
		Long:  "My CLI Tool",
	}

	completionCommand := &cobra.Command{
		Use:   "completion",
		Short: "Generates bash completion scripts",
		Long:  "To install completion scripts run:\nmy-cli-tool completion > /usr/local/etc/bash_completion.d/my-cli-tool",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenBashCompletion(os.Stdout)
		},
	}
	root.AddCommand(completionCommand)

	primaryCommand := &cobra.Command{
		Use:                   "primary [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Primary command for tool",
		Long:                  "Primary command for tool",
		RunE:                  primaryFunction,
	}
	initFlags(primaryCommand.Flags())
	root.AddCommand(primaryCommand)

	versionCommand := &cobra.Command{
		Use:                   "version",
		DisableFlagsInUseLine: true,
		Short:                 "Print the version",
		Long:                  "Print the version",
		RunE:                  versionFunction,
	}
	root.AddCommand(versionCommand)

	if err := root.Execute(); err != nil {
		panic(err)
	}
}

func versionFunction(cmd *cobra.Command, args []string) error {
	if len(version) == 0 {
		fmt.Println("development")
		return nil
	}
	fmt.Println(version)
	return nil
}

func primaryFunction(cmd *cobra.Command, args []string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()

	err := cmd.ParseFlags(args)
	if err != nil {
		return err
	}

	flag := cmd.Flags()

	v := viper.New()
	bindErr := v.BindPFlags(flag)
	if bindErr != nil {
		return bindErr
	}
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	// Create the logger
	// Remove the prefix and any datetime data
	logger := log.New(os.Stdout, "", log.LstdFlags)

	verbose := v.GetBool(VerboseFlag)
	if !verbose {
		// Disable any logging that isn't attached to the logger unless using the verbose flag
		log.SetOutput(ioutil.Discard)
		log.SetFlags(0)

		// Remove the flags for the logger
		logger.SetFlags(0)
	}

	// Check the config and exit with usage details if there is a problem
	checkConfigErr := checkConfig(v)
	if checkConfigErr != nil {
		return checkConfigErr
	}

	if verbose {
		logger.Println("Hello, universe")
	} else {
		logger.Println("Hello, world")
	}

	return nil
}
