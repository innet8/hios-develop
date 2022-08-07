package run

import (
	"github.com/innet8/hios/pkg/logger"
	"github.com/nahid/gohttp"
	"strconv"
	"strings"
	"time"
)

// ExecStart 开始执行
func ExecStart() {
	logger.Info("---------- exec start ----------")
	status := "success"
	error_ := ""
	cmdErr := ExecConf.SSHConfig.CmdAsync(ExecConf.Ip, ExecConf.Cmd)
	if cmdErr != nil {
		status = "error"
		error_ = cmdErr.Error()
	}
	if strings.HasPrefix(ExecConf.Url, "http://") || strings.HasPrefix(ExecConf.Url, "https://") {
		logger.Info("---------- callback start ----------")
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		_, err := gohttp.NewRequest().
			FormData(map[string]string{
				"ip":        ExecConf.Ip,
				"status":    status,
				"error":     error_,
				"timestamp": timestamp,
			}).
			Post(ExecConf.Url)
		if err != nil {
			logger.Info("---------- callback error ----------")
		} else {
			logger.Info("---------- callback end ----------")
		}
	}
	logger.Info("---------- exec end ----------")
}
