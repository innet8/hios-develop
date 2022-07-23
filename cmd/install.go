package cmd

import (
	"fmt"
	"github.com/nahid/gohttp"
	"github.com/spf13/cobra"
	"os"
	"runtime"
	"strings"

	"github.com/innet8/hios/run"
)

// installCmd represents the installation command
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install",
	PreRun: func(cmd *cobra.Command, args []string) {
		if strings.Contains(runtime.GOARCH, "arm") {
			run.PrintError(fmt.Sprintf(" %s arch is not supported", runtime.GOARCH))
			os.Exit(0)
		}
		if !strings.Contains(runtime.GOOS, "linux") {
			run.PrintError("Linux installation only")
			os.Exit(0)
		}
		if run.InConf.Token == "" {
			run.PrintError("The token is required")
			os.Exit(0)
		}

		if run.InConf.Server == "" {
			run.PrintError("The server are required")
			os.Exit(0)
		}

		if run.InConf.Iver == "" {
			run.PrintError("The iver (image version) are required")
			os.Exit(0)
		}

		fmt.Print("Checking arguments...")

		_, err := gohttp.NewRequest().Head(run.InConf.Server)
		if err != nil {
			run.PrintError(fmt.Sprintf("Wrong server: %s\n", err.Error()))
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
	installCmd.Flags().StringVar(&run.InConf.Iver, "iver", "", "Hicloud image version")
	installCmd.Flags().BoolVar(&run.InConf.Reset, "reset", false, "Remove before installation")
}
