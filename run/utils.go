package run

import (
	"bytes"
	"fmt"
	"github.com/nahid/gohttp"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

func PrintError(msg string) {
	fmt.Printf("\033[1;31m" + msg + " \033[0m\n")
}

func PrintSuccess(msg string) {
	fmt.Printf("\033[1;32m" + msg + " \033[0m\n")
}

func DisplayRunning(display string, done chan bool) {
	chars := []string{
		"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
	}
	d := time.NewTicker(100 * time.Millisecond)
	for {
		select {
		case <-done:
			fmt.Print("\r")
			return
		case _ = <-d.C:
			s1 := chars[:1]
			chars = append(chars[1:], s1[0])
			fmt.Printf("\r %s %s ...", s1[0], display)
		}
	}
}

// Mkdir 创建目录
func Mkdir(path string, perm os.FileMode) (err error) {
	if _, err = os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(path, perm)
		if err != nil {
			return
		}
		err = os.Chmod(path, perm)
		if err != nil {
			return
		}
	}
	return err
}

// Command 执行命令
func Command(arg ...string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("/bin/sh", arg...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// GetIp 获取IP地址
func GetIp() (ip string) {
	resp, _ := gohttp.NewRequest().Headers(map[string]string{
		"User-Agent": "curl/7.79.1",
	}).Get("http://ip.sb")

	body, _ := resp.GetBodyAsString()
	ip = strings.Trim(body, "\n\r ")
	return
}

// Exists 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

// IsDir 判断所给路径是否为文件夹
func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

// IsFile 判断所给路径是否为文件
func IsFile(path string) bool {
	return !IsDir(path)
}

// ReadFile 读取文件
func ReadFile(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(content)
}

// WriteFile 保存文件
func WriteFile(path string, content string) {
	var fileByte = []byte(content)
	err := ioutil.WriteFile(path, fileByte, 0666)
	if err != nil {
		panic(err)
	}
}

// RandString 生成随机字符串
func RandString(len int) string {
	var r *rand.Rand
	r = rand.New(rand.NewSource(time.Now().Unix()))
	bs := make([]byte, len)
	for i := 0; i < len; i++ {
		b := r.Intn(26) + 65
		bs[i] = byte(b)
	}
	return string(bs)
}
