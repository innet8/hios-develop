package cmd

import (
	"github.com/spf13/cobra"
	"os"

	"github.com/innet8/hios/run"
)

// workCmd represents the work command
var workCmd = &cobra.Command{
	Use:   "work",
	Short: "Work",
	PreRun: func(cmd *cobra.Command, args []string) {
		if os.Getenv("HI_URL") == "" {
			run.PrintError("Environment error: HI_URL")
			os.Exit(0)
		}
		if os.Getenv("HI_MODE") == "" {
			run.PrintError("Environment error: HI_MODE")
			os.Exit(0)
		}
		if os.Getenv("HI_TOKEN") == "" {
			run.PrintError("Environment error: HI_TOKEN")
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		run.WorkStart()
	},
}

func init() {
	rootCmd.AddCommand(workCmd)
}
