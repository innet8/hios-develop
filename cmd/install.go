package cmd

import (
	"fmt"
	"github.com/nahid/gohttp"
	"github.com/spf13/cobra"
	"os"

	"github.com/innet8/hios/run"
)

// installCmd represents the installation command
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install",
	PreRun: func(cmd *cobra.Command, args []string) {
		if run.InConf.Token == "" {
			run.PrintError("The token is required!")
			os.Exit(0)
		}

		if run.InConf.Server == "" {
			run.PrintError("The server-url are required!")
			os.Exit(0)
		}

		fmt.Print("Checking arguments...")

		_, err := gohttp.NewRequest().Head(run.InConf.Server)
		if err != nil {
			run.PrintError(fmt.Sprintf("Wrong server-url: %s\n", err.Error()))
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		run.InstallNode()
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.Flags().StringVar(&run.InConf.Token, "token", "", "Token")
	installCmd.Flags().StringVar(&run.InConf.Mtu, "mtu", "", "Maximum transmission unit")
	installCmd.Flags().StringVar(&run.InConf.Server, "server", "", "Server url, \"http://\" or \"https://\" prefix.")
	installCmd.Flags().StringVar(&run.InConf.Swap, "swap", "", "Add swap partition, unit MB")
	installCmd.Flags().BoolVar(&run.InConf.Reset, "reset", false, "Remove before installation")
}
