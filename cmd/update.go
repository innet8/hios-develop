package cmd

import (
	"github.com/innet8/hios/run"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(updateCmd)
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Upgrade OS",
	Run: func(cmd *cobra.Command, args []string) {
		run.UpdateStart()
	},
}
