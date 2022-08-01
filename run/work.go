package run

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/innet8/hios/pkg/logger"
	"github.com/innet8/hios/pkg/xrsa"
	"github.com/togettoyou/wsc"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	logDir   = "/usr/lib/hicloud/log"
	tmpDir   = "/usr/lib/hicloud/tmp"
	binDir   = "/usr/lib/hicloud/bin"
	sshDir   = "/usr/lib/hicloud/.ssh"
	workDir  = "/usr/lib/hicloud/work"
	startDir = "/usr/lib/hicloud/start"

	serverPublic string
	nodePublic   string
	nodePrivate  string

	connectRand string

	configUpdating bool
	configContinue string

	hostState  *State
	netIoInNic *NetIoNic

	daemonMap = make(map[string]string)
)

type msgModel struct {
	Type string    `json:"type"`
	File fileModel `json:"file"`
	Cmd  cmdModel  `json:"cmd"`
}

type fileModel struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

type cmdModel struct {
	Log      bool   `json:"log"`
	Callback string `json:"callback"`
	Content  string `json:"content"`
}

type sendModel struct {
	Type   string      `json:"type"`
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

type pingModel struct {
	Result string `json:"result"`
	Source string `json:"source"`
}

type callModel struct {
	Callback string `json:"callback"`
	Output   string `json:"output"`
	Err      string `json:"err"`
}

// WorkStart Work开始
func WorkStart() {
	if !Exists(fmt.Sprintf("%s/server_public", sshDir)) {
		logger.Error("Server public key does not exist")
		os.Exit(1)
	}
	if !Exists(fmt.Sprintf("%s/node_public", sshDir)) {
		logger.Error("Node public key does not exist")
		os.Exit(1)
	}
	if !Exists(fmt.Sprintf("%s/node_private", sshDir)) {
		logger.Error("Node private key does not exist")
		os.Exit(1)
	}
	serverPublic = ReadFile(fmt.Sprintf("%s/server_public", sshDir))
	nodePublic = ReadFile(fmt.Sprintf("%s/node_public", sshDir))
	nodePrivate = ReadFile(fmt.Sprintf("%s/node_private", sshDir))
	//
	origin := strings.Replace(os.Getenv("HI_URL"), "https://", "wss://", 1)
	origin = strings.Replace(origin, "http://", "ws://", 1)
	if strings.Count(origin, "/") > 2 {
		origins := strings.Split(origin, "/")
		origin = fmt.Sprintf("%s/%s/%s", origins[0], origins[1], origins[2])
	}
	nodeName, _ := os.Hostname()
	wsUrl := fmt.Sprintf("%s/ws?action=hios&mode=%s&token=%s&name=%s&cid=%s", origin, os.Getenv("HI_MODE"), os.Getenv("HI_TOKEN"), nodeName, os.Getenv("HI_CID"))
	//
	err := Mkdir(logDir, 0755)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to create log dir: %s\n", err.Error()))
		os.Exit(1)
	}
	_ = logger.SetLogger(`{"File":{"filename":"/usr/lib/hicloud/log/work.log","level":"TRAC","daily":true,"maxlines":100000,"maxsize":10,"maxdays":3,"append":true,"permit":"0660"}}`)
	startRun()
	//
	done := make(chan bool)
	ws := wsc.New(wsUrl)
	// 自定义配置
	ws.SetConfig(&wsc.Config{
		WriteWait:         10 * time.Second,
		MaxMessageSize:    512 * 1024, // 512KB
		MinRecTime:        2 * time.Second,
		MaxRecTime:        30 * time.Second,
		RecFactor:         1.5,
		MessageBufferSize: 1024,
	})
	// 设置回调处理
	ws.OnConnected(func() {
		logger.Debug("OnConnected: ", ws.WebSocket.Url)
		logger.SetWebsocket(ws)
		onConnected(ws)
	})
	ws.OnConnectError(func(err error) {
		logger.Debug("OnConnectError: ", err.Error())
	})
	ws.OnDisconnected(func(err error) {
		logger.Debug("OnDisconnected: ", err.Error())
	})
	ws.OnClose(func(code int, text string) {
		logger.Debug("OnClose: ", code, text)
		done <- true
	})
	ws.OnTextMessageSent(func(message string) {
		logger.Debug("OnTextMessageSent: ", message)
	})
	ws.OnBinaryMessageSent(func(data []byte) {
		logger.Debug("OnBinaryMessageSent: ", string(data))
	})
	ws.OnSentError(func(err error) {
		logger.Debug("OnSentError: ", err.Error())
	})
	ws.OnPingReceived(func(appData string) {
		logger.Debug("OnPingReceived: ", appData)
	})
	ws.OnPongReceived(func(appData string) {
		logger.Debug("OnPongReceived: ", appData)
	})
	ws.OnTextMessageReceived(func(message string) {
		logger.Debug("OnTextMessageReceived: ", message)
		// 判断数据解密
		if strings.HasPrefix(message, "r:") {
			message = xrsa.Decrypt(message[2:], nodePublic, nodePrivate)
		}
		handleMessageReceived(ws, message)
	})
	ws.OnBinaryMessageReceived(func(data []byte) {
		logger.Debug("OnBinaryMessageReceived: ", string(data))
	})
	// 开始连接
	go ws.Connect()
	for {
		select {
		case <-done:
			return
		}
	}
}

// 连接成功
func onConnected(ws *wsc.Wsc) {
	connectRand = RandString(6)
	go func() {
		// 每10秒任务
		r := connectRand
		t := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-t.C:
				if r != connectRand {
					return
				}
				err := timedTaskA(ws)
				if err != nil {
					logger.Debug("TimedTaskA: %s", err)
				}
				if err == wsc.CloseErr {
					return
				}
			}
		}
	}()
	go func() {
		// 每50秒任务
		r := connectRand
		t := time.NewTicker(50 * time.Second)
		for {
			select {
			case <-t.C:
				if r != connectRand {
					return
				}
				err := timedTaskB(ws)
				if err != nil {
					logger.Debug("TimedTaskB: %s", err)
				}
				if err == wsc.CloseErr {
					return
				}
			}
		}
	}()
}

// 启动运行
func startRun() {
	_ = os.RemoveAll(tmpDir)
	_ = os.MkdirAll(tmpDir, os.ModePerm)
	//
	_ = os.MkdirAll(startDir, os.ModePerm)
	path := fmt.Sprintf(startDir)
	files, err := filepath.Glob(filepath.Join(path, "*"))
	if err != nil {
		logger.Error(err)
	}
	for i := range files {
		file := files[i]
		content := ReadFile(file)
		_, _ = Cmd("-c", content)
	}
}

// 定时任务A（上报：系统状态、入口网速）
func timedTaskA(ws *wsc.Wsc) error {
	hiMode := os.Getenv("HI_MODE")
	sendMessage := ""
	if hiMode == "host" {
		hostState = GetHostState(hostState)
		if hostState != nil {
			value, err := json.Marshal(hostState)
			if err != nil {
				logger.Error("State host: %s", err)
			} else {
				sendMessage = formatSendMsg("state", string(value))
			}
		}
	} else if hiMode == "hihub" {
		netIoInNic = GetNetIoInNic(netIoInNic)
		if netIoInNic != nil {
			value, err := json.Marshal(netIoInNic)
			if err != nil {
				logger.Error("NetIoInNic: %s", err)
			} else {
				sendMessage = formatSendMsg("netio", string(value))
			}
		}
	}
	if sendMessage != "" {
		return ws.SendTextMessage(sendMessage)
	}
	return nil
}

// 定时任务B（上报：ping结果、流量统计）
func timedTaskB(ws *wsc.Wsc) error {
	hiMode := os.Getenv("HI_MODE")
	sendMessage := ""
	if hiMode == "hihub" {
		// 公网 ping
		sendErr := pingFileAndSend(ws, fmt.Sprintf("%s/ips", workDir), "")
		if sendErr != nil {
			return sendErr
		}
		// 专线 ping
		dirPath := fmt.Sprintf("%s/vpc_ip", workDir)
		if IsDir(dirPath) {
			files := getIpsFiles(dirPath)
			if files != nil {
				for _, file := range files {
					go func(file string) {
						_ = pingFileAndSend(ws, fmt.Sprintf("%s/%s.ips", dirPath, file), file)
					}(file)
				}
			}
		}
		// wg 流量统计 todo
	} else {
		// 发送刷新
		sendMessage = formatSendMsg("refresh", time.Now().Unix())
	}
	if sendMessage != "" {
		return ws.SendTextMessage(sendMessage)
	}
	return nil
}

// 获取目录下的所有ips文件
func getIpsFiles(dirPath string) []string {
	dir, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil
	}
	var files []string
	for _, fi := range dir {
		if !fi.IsDir() {
			ok := strings.HasSuffix(fi.Name(), ".ips")
			if ok {
				basename := strings.TrimSuffix(fi.Name(), ".ips")
				if StringToIP(basename) != nil { // xxx.xxx.xxx.xxx.ips
					files = append(files, basename)
				} else if strings.Contains(basename, "_") { // xxx.xxx.xxx.xxx(_xx)+.ips
					ip := strings.Split(basename, "_")[0]
					if StringToIP(ip) != nil {
						files = append(files, basename)
					}
				}
			}
		}
	}
	return files
}

// ping 文件并发送
func pingFileAndSend(ws *wsc.Wsc, fileName string, source string) error {
	originalSource := source
	if strings.Contains(source, "_") {
		source = strings.Split(source, "_")[0]
	}
	if !Exists(fileName) {
		logger.Debug("File no exist [%s]", fileName)
		return nil
	}
	logger.Debug("Start ping [%s]", fileName)
	result, err := pingFile(fileName, source)
	if err != nil {
		logger.Debug("Ping error [%s]: %s", fileName, err)
		return nil
	}
	pingData := &pingModel{Result: result, Source: originalSource}
	sendMessage := formatSendMsg("ping", pingData)
	return ws.SendTextMessage(sendMessage)
}

// ping文件
func pingFile(path string, source string) (string, error) {
	result, err := pingFileMap(path, source, 2000, 5)
	if err != nil {
		return "", err
	}
	value, errJson := json.Marshal(result)
	return string(value), errJson
}

// 遍历ping文件内ip，并返回ping键值（最小）
func pingFileMap(path string, source string, timeout int, count int) (map[string]float64, error) {
	cmd := fmt.Sprintf("fping -A -u -q -4 -t %d -c %d -f %s", timeout, count, path)
	if source != "" {
		cmd = fmt.Sprintf("fping -A -u -q -4 -S %s -t %d -c %d -f %s", source, timeout, count, path)
	}
	output, err := Cmd("-c", cmd)
	if output == "" && err != nil {
		return nil, err
	}
	output = strings.Replace(output, " ", "", -1)
	spaceRe, errRe := regexp.Compile(`[/:=]`)
	if errRe != nil {
		return nil, err
	}
	var pingMap = make(map[string]float64)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		s := spaceRe.Split(scanner.Text(), -1)
		if len(s) > 9 {
			float, _ := strconv.ParseFloat(s[9], 64)
			pingMap[s[0]] = float
		} else {
			pingMap[s[0]] = 0
		}
	}
	return pingMap, nil
}

// 处理消息
func handleMessageReceived(ws *wsc.Wsc, message string) {
	var data msgModel
	if ok := json.Unmarshal([]byte(message), &data); ok == nil {
		if data.Type == "file" {
			// 保存文件
			handleMessageFile(data.File, false)
		} else if data.Type == "cmd" {
			// 执行命令
			output, err := handleMessageCmd(data.Cmd.Content, data.Cmd.Log)
			if len(data.Cmd.Callback) > 0 {
				cmderr := ""
				if err != nil {
					cmderr = err.Error()
				}
				callData := &callModel{
					Callback: data.Cmd.Callback,
					Output:   output,
					Err:      cmderr}
				sendMessage := formatSendMsg("cmd", callData)
				err = ws.SendTextMessage(sendMessage)
				if err != nil {
					logger.Debug("Send cmd callback error: %s", err)
				}
			}
		}
	}
}

// 格式化要发送的消息
func formatSendMsg(action string, data interface{}) string {
	sendData := &sendModel{Type: "node", Action: action, Data: data}
	sendRes, sendErr := json.Marshal(sendData)
	if sendErr != nil {
		return ""
	}
	msg := string(sendRes)
	if len(serverPublic) > 0 {
		return fmt.Sprintf("r:%s", xrsa.Encrypt(msg, serverPublic))
	} else {
		return msg
	}
}

// 保存文件或运行文件
func handleMessageFile(fileData fileModel, force bool) {
	var err error
	fileName := ""
	if strings.HasPrefix(fileData.Path, "/") {
		fileName = fileData.Path
	} else {
		fileName = fmt.Sprintf("%s/%s", workDir, fileData.Path)
	}
	fileDir := filepath.Dir(fileName)
	if !Exists(fileDir) {
		err = os.MkdirAll(fileDir, os.ModePerm)
		if err != nil {
			logger.Error("Mkdir error: [%s] %s", fileDir, err)
			return
		}
	}
	fileContent := fileData.Content
	if fileContent == "" {
		logger.Warn("File empty: %s", fileName)
		return
	}
	//
	fileKey := StringMd5(fileName)
	contentKey := StringMd5(fileContent)
	if !force {
		md5Value, _ := FileMd5.Load(fileKey)
		if md5Value != nil && md5Value.(string) == contentKey {
			logger.Debug("File same: %s", fileName)
			return
		}
	}
	FileMd5.Store(fileKey, contentKey)
	//
	var output string
	var fileByte = []byte(fileContent)
	err = ioutil.WriteFile(fileName, fileByte, 0666)
	if err != nil {
		logger.Error("WriteFile error: [%s] %s", fileName, err)
		return
	}
	if fileData.Type == "exec" {
		logger.Info("Exec file start: [%s]", fileName)
		_, _ = Cmd("-c", fmt.Sprintf("chmod +x %s", fileName))
		output, err = Cmd(fileName)
		if err != nil {
			logger.Error("Exec file error: [%s] %s %s", fileName, err, output)
		} else {
			logger.Info("Exec file success: [%s]", fileName)
		}
	} else if fileData.Type == "yml" {
		logger.Info("Run yml start: [%s]", fileName)
		cmd := fmt.Sprintf("cd %s && docker-compose up -d --remove-orphans", fileDir)
		output, err = Cmd("-c", cmd)
		if err != nil {
			logger.Error("Run yml error: [%s] %s %s", fileName, err, output)
		} else {
			logger.Info("Run yml success: [%s]", fileName)
		}
	} else if fileData.Type == "nginx" {
		logger.Info("Run nginx start: [%s]", fileName)
		output, err = Cmd("-c", "nginx -s reload")
		if err != nil {
			logger.Error("Run nginx error: [%s] %s %s", fileName, err, output)
		} else {
			logger.Info("Run nginx success: [%s]", fileName)
		}
	} else if fileData.Type == "danted" {
		program := fmt.Sprintf("danted -f %s", fileName)
		killPsef(program)
		time.Sleep(1 * time.Second)
		logger.Info("Run danted start: [%s]", fileName)
		cmd := fmt.Sprintf("%s > /dev/null 2>&1 &", program)
		output, err = Cmd("-c", cmd)
		if err != nil {
			logger.Error("Run danted error: [%s] %s %s", fileName, err, output)
		} else {
			logger.Info("Run danted success: [%s]", fileName)
			daemonStart(program, fileData)
		}
	} else if fileData.Type == "xray" {
		program := fmt.Sprintf("%s/xray run -c %s", binDir, fileName)
		killPsef(program)
		time.Sleep(1 * time.Second)
		logger.Info("Run xray start: [%s]", fileName)
		cmd := fmt.Sprintf("%s > /dev/null 2>&1 &", program)
		output, err = Cmd("-c", cmd)
		if err != nil {
			logger.Error("Run xray error: [%s] %s %s", fileName, err, output)
		} else {
			logger.Info("Run xray success: [%s]", fileName)
			daemonStart(program, fileData)
		}
	} else if fileData.Type == "configure" {
		updateConfigure(fileName, 0)
	}
}

// 运行自定义脚本
func handleMessageCmd(cmd string, addLog bool) (string, error) {
	output, err := Cmd("-c", cmd)
	if addLog {
		if err != nil {
			logger.Error("Run cmd error: [%s] %s; output: [%s]", cmd, err, output)
		} else {
			logger.Info("Run cmd success: [%s]", cmd)
		}
	}
	return output, err
}

// 更新configure
func updateConfigure(fileName string, againNum int) {
	if configUpdating {
		logger.Info("Run configure wait: [%s]", fileName)
		configContinue = fileName
		return
	}
	configContinue = ""
	configUpdating = true
	//
	go func() {
		logger.Info("Run configure start: [%s]", fileName)
		ch := make(chan int)
		var err error
		go func() {
			cmd := fmt.Sprintf("%s/entrypoint.sh load %s", binDir, fileName)
			_, err = Cmd("-c", cmd)
			ch <- 1
		}()
		select {
		case <-ch:
			if err != nil {
				logger.Error("Run configure error: [%s] %s", fileName, err)
			} else {
				logger.Info("Run configure success: [%s]", fileName)
			}
		case <-time.After(time.Second * 180):
			logger.Error("Run configure timeout: [%s]", fileName)
			err = errors.New("timeout")
		}
		if err != nil {
			time.Sleep(10 * time.Second)
		}
		configUpdating = false
		if len(configContinue) > 0 {
			logger.Info("Run configure continue: [%s]", configContinue)
			updateConfigure(configContinue, 0)
		} else if err != nil && againNum < 10 {
			againNum = againNum + 1
			logger.Info("Run configure again: [%s] take %d", fileName, againNum)
			updateConfigure(fileName, againNum)
		}
	}()
}

// 杀死根据 ps -ef 查出来的
func killPsef(value string) {
	cmd := fmt.Sprintf("ps -ef | grep '%s' | grep -v 'grep' | awk '{print $2}'", value)
	output, _ := Cmd("-c", cmd)
	if len(output) > 0 {
		sc := bufio.NewScanner(strings.NewReader(output))
		for sc.Scan() {
			if len(sc.Text()) > 0 {
				_, _ = Cmd("-c", fmt.Sprintf("kill -9 %s", sc.Text()))
			}
		}
	}
}

// 守护进程
func daemonStart(value string, fileData fileModel) {
	// 每10秒检测一次
	rand := RandString(6)
	daemonMap[value] = rand
	go func() {
		t := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-t.C:
				if daemonMap[value] != rand {
					return
				}
				cmd := fmt.Sprintf("ps -ef | grep '%s' | grep -v 'grep'", value)
				output, _ := Cmd("-c", cmd)
				if len(output) == 0 {
					handleMessageFile(fileData, true)
					return
				}
			}
		}
	}()
}
