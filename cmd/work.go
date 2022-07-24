package cmd

import (
	"github.com/innet8/hios/pkg/logger"
	"github.com/spf13/cobra"
	"os"

	"github.com/innet8/hios/run"
)

// workCmd represents the websocket command
var workCmd = &cobra.Command{
	Use:   "work",
	Short: "Work",
	PreRun: func(cmd *cobra.Command, args []string) {
		if run.WorkConf.Server == "" {
			run.WorkConf.Server = run.WorkServer()
		}
		if run.WorkConf.Server == "" {
			run.PrintError("The server are required")
			os.Exit(0)
		}
		logger.Debug("WorkServer: ", run.WorkConf.Server)
	},
	Run: func(cmd *cobra.Command, args []string) {
		run.WorkStart()
	},
}

func init() {
	rootCmd.AddCommand(workCmd)
	workCmd.Flags().StringVar(&run.WorkConf.Server, "server", "", "Websocket server url, \"ws://\" or \"wss://\" prefix.")
}
