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
		if len(run.ExecConf.Host) == 0 || run.ExecConf.Cmd == "" {
			run.PrintError("host/cmd required.")
			os.Exit(0)
		}
		ip := run.ExecConf.Host
		port := "22"
		if ipport := strings.Split(run.ExecConf.Host, ":"); len(ipport) == 2 {
			ip = ipport[0]
			port = ipport[1]
		}
		if run.StringToIP(ip) == nil {
			run.PrintError(fmt.Sprintf("ip [%s] is invalid", ip))
			os.Exit(1)
		}
		run.ExecConf.Host = fmt.Sprintf("%s:%s", ip, port)
		if run.ExecConf.SSHConfig.User == "" {
			run.ExecConf.SSHConfig.User = "root"
		}
		if run.ExecConf.SSHConfig.Password != "" {
			run.ExecConf.SSHConfig.Password = run.Base64Decode(run.ExecConf.SSHConfig.Password)
		}
		if run.ExecConf.SSHConfig.PkFile != "" {
			run.ExecConf.SSHConfig.PkPassword = run.ExecConf.SSHConfig.Password
		}
		if len(run.ExecConf.Cmd) > 0 {
			run.ExecConf.Cmd = run.Base64Decode(run.ExecConf.Cmd)
		}
		if len(run.ExecConf.Param) > 0 {
			run.ExecConf.Param = run.Base64Decode(run.ExecConf.Param)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		run.ExecStart()
	},
}

func init() {
	rootCmd.AddCommand(execCmd)
	execCmd.Flags().StringVar(&run.ExecConf.Host, "host", "", "192.168.0.5 or 192.168.0.5:22")
	execCmd.Flags().StringVar(&run.ExecConf.SSHConfig.User, "user", "root", "User, default: root")
	execCmd.Flags().StringVar(&run.ExecConf.SSHConfig.Password, "password", "", "Password, it’s base64 encode (If set pkfile, it is the password for pkfile)")
	execCmd.Flags().StringVar(&run.ExecConf.SSHConfig.PkFile, "pkfile", "", "Key path, if set, log in with key")
	execCmd.Flags().StringVar(&run.ExecConf.Cmd, "cmd", "", "Command, get url content exec for \"content://\" prefix, it’s base64 encode")
	execCmd.Flags().StringVar(&run.ExecConf.Param, "param", "", "Parameter, it’s base64 encode")
	execCmd.Flags().StringVar(&run.ExecConf.Url, "url", "", "Callback url, \"http://\" or \"https://\" prefix")
	execCmd.Flags().StringVar(&run.ExecConf.LogFile, "log", "", "Log file path")
}
