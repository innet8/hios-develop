package run

import (
	"encoding/json"
	"fmt"
	"github.com/c4milo/unpackit"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
		log.Fatal("Hios is not installed")
	}
	destPath := downloadLatest()
	copyHiosFile(destPath)
	restartHios()
	fmt.Println("Update completed")
}

func downloadLatest() string {
	// get version
	data, err := http.Get("https://api.github.com/repos/innet8/hios/releases/latest")
	if err != nil {
		log.Fatal(err.Error())
	}
	b, err := ioutil.ReadAll(data.Body)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err.Error())
	}
	destPath, err := unpackit.Unpack(resp.Body, "")
	if err != nil {
		log.Fatal(err)
	}
	return destPath
}

func copyHiosFile(srcPath string) {
	if _, err := copyFile(filepath.Join(srcPath, "hios"), binPath); err != nil {
		log.Fatalln(err)
	} else {
	}
	_ = os.Chmod(binPath, 0755)
}

func restartHios() {
	var err error
	if IsFile("/usr/sbin/hicloud") {
		// hihub
		KillPsef(binPath)
		_, err = Cmd("-c", "/usr/sbin/hicloud")
	} else {
		// host
		_, err = Cmd("-c", "supervisorctl restart hios")
	}
	if err != nil {
		log.Fatalln(err)
	}
}

//生成目录并拷贝文件
func copyFile(src, dest string) (w int64, err error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return
	}
	defer srcFile.Close()
	//分割path目录
	destSplitPathDirs := strings.Split(dest, string(filepath.Separator))

	//检测时候存在目录
	destSplitPath := ""
	for index, dir := range destSplitPathDirs {
		if index < len(destSplitPathDirs)-1 {
			destSplitPath = destSplitPath + dir + string(filepath.Separator)
			if !Exists(destSplitPath) {
				log.Println("mkdir:" + destSplitPath)
				//创建目录
				err = os.Mkdir(destSplitPath, os.ModePerm)
				if err != nil {
					log.Fatalln(err)
				}
			}
		}
	}
	dstFile, err := os.Create(dest)
	if err != nil {
		return
	}
	defer dstFile.Close()

	return io.Copy(dstFile, srcFile)
}
