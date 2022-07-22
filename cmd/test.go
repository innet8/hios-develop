package cmd

import (
	"github.com/innet8/hios/install"
	"github.com/spf13/cobra"
)

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test",
	Run: func(cmd *cobra.Command, args []string) {
		install.BuildTest()
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
}
