package cmd

import (
	"github.com/innet8/hios/run"
	"github.com/spf13/cobra"
	"os"
)

// rsaCmd represents the rsa command
var rsaCmd = &cobra.Command{
	Use:   "rsa",
	Short: "Rsa",
	PreRun: func(cmd *cobra.Command, args []string) {
		if run.RsaConf.Path == "" {
			run.PrintError("The path are required")
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		run.BuildRsa()
	},
}

func init() {
	rootCmd.AddCommand(rsaCmd)
	rsaCmd.Flags().StringVar(&run.RsaConf.Path, "path", "", "")
}
