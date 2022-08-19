package run

import (
	"encoding/json"
	"fmt"
	"github.com/c4milo/unpackit"
	"github.com/innet8/hios/pkg/logger"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

var (
	binPath = "/usr/lib/hicloud/bin/hios"
)

type release struct {
	TagName string `json:"tag_name"`
}

//UpdateStart is
func UpdateStart() {
	if !IsFile(binPath) {
		logger.Fatal("Hios is not installed")
	}
	destPath := downloadLatest()
	copyHios(destPath)
	restartHios()
	fmt.Println("Update completed")
}

func downloadLatest() string {
	// get version
	data, err := http.Get("https://api.github.com/repos/innet8/hios/releases/latest")
	if err != nil {
		logger.Fatal(err.Error())
	}
	b, err := ioutil.ReadAll(data.Body)
	if err != nil {
		logger.Fatal(err)
	}
	rl := new(release)
	_ = json.Unmarshal(b, &rl)
	version := rl.TagName
	fmt.Println("the latest version is", version)
	filename := runtime.GOOS + "-" + runtime.GOARCH + "-hios.tar.gz"
	// download the latest package
	downloadUrl := fmt.Sprintf("https://github.com/innet8/hios/releases/download/%s/%s", version, filename)
	fmt.Println("download package from ", downloadUrl)
	resp, err := http.Get(downloadUrl)
	if err != nil {
		logger.Fatal(err.Error())
	}
	destPath, err := unpackit.Unpack(resp.Body, "")
	if err != nil {
		logger.Fatal(err)
	}
	return destPath
}

func copyHios(srcPath string) {
	if IsFile(binPath) {
		_ = os.Remove(binPath)
	}

	srcFile, err := os.Open(filepath.Join(srcPath, "hios"))
	if err != nil {
		logger.Fatal(err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(binPath)
	if err != nil {
		logger.Fatal(err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		logger.Fatal(err)
	}

	_ = os.Chmod(binPath, 0755)
}

func restartHios() {
	var err error
	if IsFile("/usr/sbin/hicloud") {
		// hihub
		KillPsef(fmt.Sprintf("%s work", binPath))
		_, err = Cmd("-c", "/usr/sbin/hicloud")
	} else {
		// host
		_, err = Cmd("-c", "supervisorctl restart hios")
	}
	if err != nil {
		logger.Fatal(err)
	}
}
