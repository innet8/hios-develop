package cmd

import (
	"fmt"
	"github.com/innet8/hios/run"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec",
	Short: "Exec",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(run.ExecConf.Ip) == 0 || run.ExecConf.Cmd == "" || run.ExecConf.Url == "" {
			run.PrintError("ip/cmd/url required.")
			os.Exit(0)
		}
		ip := run.ExecConf.Ip
		port := "22"
		if ipport := strings.Split(run.ExecConf.Ip, ":"); len(ipport) == 2 {
			ip = ipport[0]
			port = ipport[1]
		}
		if run.StringToIP(ip) == nil {
			run.PrintError(fmt.Sprintf("ip [%s] is invalid", ip))
			os.Exit(1)
		}
		run.ExecConf.Ip = fmt.Sprintf("%s:%s", ip, port)
		if run.ExecConf.SSHConfig.User == "" {
			run.ExecConf.SSHConfig.User = "root"
		}
		if run.ExecConf.SSHConfig.Password != "" {
			run.ExecConf.SSHConfig.Password = run.Base64Decode(run.ExecConf.SSHConfig.Password)
		}
		if len(run.ExecConf.Cmd) > 0 {
			run.ExecConf.Cmd = run.Base64Decode(run.ExecConf.Cmd)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		run.ExecStart()
	},
}

func init() {
	rootCmd.AddCommand(execCmd)
	execCmd.Flags().StringVar(&run.ExecConf.Ip, "ip", "", "192.168.0.5")
	execCmd.Flags().StringVar(&run.ExecConf.SSHConfig.User, "user", "root", "Servers user name for ssh")
	execCmd.Flags().StringVar(&run.ExecConf.SSHConfig.Password, "password", "", "Password for ssh, It’s base64 encode")
	execCmd.Flags().StringVar(&run.ExecConf.Cmd, "cmd", "", "Command, It’s base64 encode")
	execCmd.Flags().StringVar(&run.ExecConf.Url, "url", "", "Callback url, \"http://\" or \"https://\" prefix")
}
