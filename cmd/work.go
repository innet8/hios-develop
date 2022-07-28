package cmd

import (
	"github.com/spf13/cobra"
	"os"

	"github.com/innet8/hios/run"
)

// workCmd represents the websocket command
var workCmd = &cobra.Command{
	Use:   "work",
	Short: "Work",
	PreRun: func(cmd *cobra.Command, args []string) {
		if os.Getenv("SERVER_URL") == "" {
			run.PrintError("Environment error: SERVER_URL")
			os.Exit(0)
		}
		if os.Getenv("NODE_MODE") == "" {
			run.PrintError("Environment error: NODE_MODE")
			os.Exit(0)
		}
		if os.Getenv("NODE_TOKEN") == "" {
			run.PrintError("Environment error: NODE_TOKEN")
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
