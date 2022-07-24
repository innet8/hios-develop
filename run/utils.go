package run

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/innet8/hios/pkg/logger"
	"github.com/innet8/hios/pkg/sys"
	"github.com/nahid/gohttp"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	gopsnet "github.com/shirou/gopsutil/net"
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

// StringMd5 MD5
func StringMd5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// InArray 元素是否存在数组中
func InArray(item string, items []string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

// Base64Encode Base64加密
func Base64Encode(data string) string {
	sEnc := base64.StdEncoding.EncodeToString([]byte(data))
	return fmt.Sprintf(sEnc)
}

// Base64Decode Base64解密
func Base64Decode(data string) string {
	uDec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		logger.Warn("Error decoding string: %s ", err.Error())
		return ""
	}
	return string(uDec)
}

// GetManageState 获取主容器的状态
func GetManageState(lastState *State) *State {
	now := time.Now()
	state := &State{
		T: now,
	}

	percents, err := cpu.Percent(0, false)
	if err != nil {
		logger.Warn("get cpu percent failed:", err)
	} else {
		state.Cpu = percents[0]
	}

	upTime, err := host.Uptime()
	if err != nil {
		logger.Warn("get uptime failed:", err)
	} else {
		state.Uptime = upTime
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		logger.Warn("get virtual memory failed:", err)
	} else {
		state.Mem.Current = memInfo.Used
		state.Mem.Total = memInfo.Total
	}

	swapInfo, err := mem.SwapMemory()
	if err != nil {
		logger.Warn("get swap memory failed:", err)
	} else {
		state.Swap.Current = swapInfo.Used
		state.Swap.Total = swapInfo.Total
	}

	distInfo, err := disk.Usage("/")
	if err != nil {
		logger.Warn("get dist usage failed:", err)
	} else {
		state.Disk.Current = distInfo.Used
		state.Disk.Total = distInfo.Total
	}

	avgState, err := load.Avg()
	if err != nil {
		logger.Warn("get load avg failed:", err)
	} else {
		state.Loads = []float64{avgState.Load1, avgState.Load5, avgState.Load15}
	}

	ioStats, err := gopsnet.IOCounters(false)
	if err != nil {
		logger.Warn("get io counters failed:", err)
	} else if len(ioStats) > 0 {
		ioStat := ioStats[0]
		state.NetTraffic.Sent = ioStat.BytesSent
		state.NetTraffic.Recv = ioStat.BytesRecv

		if lastState != nil {
			duration := now.Sub(lastState.T)
			seconds := float64(duration) / float64(time.Second)
			up := uint64(float64(state.NetTraffic.Sent-lastState.NetTraffic.Sent) / seconds)
			down := uint64(float64(state.NetTraffic.Recv-lastState.NetTraffic.Recv) / seconds)
			state.NetIO.Up = up
			state.NetIO.Down = down
		}
	} else {
		logger.Warn("can not find io counters")
	}

	state.TcpCount, err = sys.GetTCPCount()
	if err != nil {
		logger.Warn("get tcp connections failed:", err)
	}

	state.UdpCount, err = sys.GetUDPCount()
	if err != nil {
		logger.Warn("get udp connections failed:", err)
	}

	return state
}

// GetNetIoInNic 获取入口网卡的网速
func GetNetIoInNic(lastNetIoNic *NetIoNic) *NetIoNic {
	ioStats, err := gopsnet.IOCounters(true)
	if err != nil {
		logger.Warn("get io counters failed:", err)
	} else if len(ioStats) > 0 {
		stat := gopsnet.IOCountersStat{
			Name: "all",
		}
		for _, nic := range ioStats {
			if strings.HasSuffix(nic.Name, "wgi_") {
				stat.BytesRecv += nic.BytesRecv
				stat.PacketsRecv += nic.PacketsRecv
				stat.Errin += nic.Errin
				stat.Dropin += nic.Dropin
				stat.BytesSent += nic.BytesSent
				stat.PacketsSent += nic.PacketsSent
				stat.Errout += nic.Errout
				stat.Dropout += nic.Dropout
			}
		}
		now := time.Now()
		netIoNic := &NetIoNic{
			T:    now,
			Sent: stat.BytesSent,
			Recv: stat.BytesRecv,
		}
		if lastNetIoNic != nil {
			duration := now.Sub(lastNetIoNic.T)
			seconds := float64(duration) / float64(time.Second)
			up := uint64(float64(netIoNic.Sent-lastNetIoNic.Sent) / seconds)
			down := uint64(float64(netIoNic.Recv-lastNetIoNic.Recv) / seconds)
			netIoNic.Up = up
			netIoNic.Down = down
		}
		return netIoNic
	} else {
		logger.Warn("can not find io counters")
	}
	return nil
}
