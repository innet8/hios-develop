package run

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nahid/gohttp"
)

var (
	baseDir  = "/usr/lib/hicloud/install"
	baseFile = "/usr/lib/hicloud/install/base"
	hiosFile = "/usr/lib/hicloud/hios"
)

func InstallNode() {

	done := make(chan bool)
	go DisplayRunning("Installing", done)

	nodeName, _, err := Command("-c", "hostname")
	if err == nil {
		nodeName = strings.Trim(nodeName, "\n\r ")
	}

	// 创建目录
	err = Mkdir(baseDir, 0755)
	if err != nil {
		InstallPrintResult(done, fmt.Sprintf("Failed to create home dir: %s\n", err.Error()))
		return
	}

	// 安装 hios
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	stdOut, stdErr, err := Command("-c", fmt.Sprintf("/bin/cp -rf %s %s", exPath, hiosFile))
	if err != nil {
		InstallPrintResult(done, fmt.Sprintf("Failed to install the hios file: %s, %s\n", stdOut, stdErr))
		return
	}

	// 生成base文件，并赋可执行权限
	WriteFile(baseFile, InstallBase(nodeName))
	err = os.Chmod(baseFile, 0755)
	if err != nil {
		InstallPrintResult(done, fmt.Sprintf("Failed to create base file: %s\n", err.Error()))
		return
	}

	// 重装执行
	if InConf.Reset {
		// 执行删除命令
		stdOut, stdErr, err = Command("-c", fmt.Sprintf("%s remove", baseFile))
		if err != nil {
			InstallPrintResult(done, fmt.Sprintf("Failed to execute remove command: %s %s\n", stdOut, stdErr))
			return
		}
	}

	// 执行安装命令
	stdOut, stdErr, err = Command("-c", fmt.Sprintf("%s install", baseFile))
	if err != nil {
		InstallPrintResult(done, fmt.Sprintf("Failed to execute installation command: %s, %s\n", stdOut, stdErr))
		return
	}

	scriptInstallDone(done, nodeName)
}

func scriptInstallDone(done chan bool, nodeName string) {

	result, _ := ioutil.ReadFile("/tmp/.hicloud_installed")
	res := strings.Trim(string(result), "\r\n")

	if res == "success" {
		if InConf.Mtu == "" {
			InConf.Mtu = "1360"
		}

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		resp, err := gohttp.NewRequest().
			FormData(map[string]string{
				"name":      nodeName,
				"token":     InConf.Token,
				"mtu":       InConf.Mtu,
				"timestamp": timestamp,
			}).
			Post(fmt.Sprintf("%s/node/install", InConf.Server))

		if err != nil || resp == nil {
			InstallPrintResult(done, fmt.Sprintf("Failed to report node installation: %s\n", err.Error()))
			return
		}

		body, err := resp.GetBodyAsString()
		if err != nil {
			InstallPrintResult(done, fmt.Sprintf("Failed to report node installation, occurred an error when get response body: %s\n", err.Error()))
			return
		}
		if body != "success" {
			InstallPrintResult(done, fmt.Sprintf("Failed to report node installation, got response: %s\n", body))
			return
		}
		done <- true
		time.Sleep(500 * time.Microsecond)
		PrintSuccess("Install success")
	} else {
		InstallPrintResult(done, res)
	}
}

func InstallPrintResult(done chan bool, error string) {
	done <- true
	time.Sleep(500 * time.Microsecond)
	PrintError(error)
	_ = os.RemoveAll(baseDir)
}
