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
		if run.RsaConf.Public == "" {
			run.PrintError("The public path are required")
			os.Exit(0)
		}
		if run.RsaConf.Private == "" {
			run.PrintError("The private path are required")
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		run.BuildRsa()
	},
}

func init() {
	rootCmd.AddCommand(rsaCmd)
	rsaCmd.Flags().StringVar(&run.RsaConf.Public, "public", "", "Public path")
	rsaCmd.Flags().StringVar(&run.RsaConf.Private, "private", "", "Private path")
}
