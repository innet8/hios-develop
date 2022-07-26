package run

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/innet8/hios/pkg/logger"
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
	workDir  = "/usr/lib/hicloud/work"
	startDir = "/usr/lib/hicloud/start"

	connectRand string
	hostState   *State
	netIoInNic  *NetIoNic

	daemonMap = make(map[string]string)
)

// WorkServer 通过文件获取Work服务器
func WorkServer() string {
	serverFile := fmt.Sprintf("%s/.hios-work-server", binDir)
	if Exists(serverFile) {
		content := strings.TrimSpace(ReadFile(serverFile))
		if strings.HasPrefix(content, "ws://") || strings.HasPrefix(content, "wss://") {
			return content
		}
	}
	return ""
}

// WorkStart Work开始
func WorkStart() {
	nodeMode := os.Getenv("NODE_MODE")
	if nodeMode == "" {
		logger.Error("System env is error")
		os.Exit(1)
	}
	err := Mkdir(logDir, 0755)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to create log dir: %s\n", err.Error()))
		os.Exit(1)
	}
	_ = logger.SetLogger(`{"File":{"filename":"/usr/lib/hicloud/log/work.log","level":"TRAC","daily":true,"maxlines":100000,"maxsize":10,"maxdays":3,"append":true,"permit":"0660"}}`)
	startRun()
	//
	done := make(chan bool)
	ws := wsc.New(WorkConf.Server)
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
		_, _, _ = Command("-c", content)
	}
}

// 定时任务A（上报：系统状态、入口网速）
func timedTaskA(ws *wsc.Wsc) error {
	nodeMode := os.Getenv("NODE_MODE")
	sendMessage := ""
	if nodeMode == "host" {
		hostState = GetHostState(hostState)
		if hostState != nil {
			value, err := json.Marshal(hostState)
			if err != nil {
				logger.Error("State host: %s", err)
			} else {
				sendMessage = fmt.Sprintf(`{"type":"node","action":"state","data":"%s"}`, Base64Encode(string(value)))
			}
		}
	} else if nodeMode == "hihub" {
		netIoInNic = GetNetIoInNic(netIoInNic)
		if netIoInNic != nil {
			value, err := json.Marshal(netIoInNic)
			if err != nil {
				logger.Error("NetIoInNic: %s", err)
			} else {
				sendMessage = fmt.Sprintf(`{"type":"node","action":"netio","data":"%s"}`, Base64Encode(string(value)))
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
	nodeMode := os.Getenv("NODE_MODE")
	sendMessage := ""
	if nodeMode == "host" {
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
	} else {
		// 发送刷新
		sendMessage = fmt.Sprintf(`{"type":"node","action":"refresh","data":"%d"}`, time.Now().Unix())
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
	sendMessage := fmt.Sprintf(`{"type":"node","action":"ping","data":"%s","source":"%s"}`, Base64Encode(result), originalSource)
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
	_, result, err := Command("-c", cmd)
	if result == "" && err != nil {
		return nil, err
	}
	result = strings.Replace(result, " ", "", -1)
	spaceRe, errRe := regexp.Compile(`[/:=]`)
	if errRe != nil {
		return nil, err
	}
	var pingMap = make(map[string]float64)
	scanner := bufio.NewScanner(strings.NewReader(result))
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
	var data map[string]interface{}
	if ok := json.Unmarshal([]byte(message), &data); ok == nil {
		content, _ := data["content"].(string)
		if data["type"] == "nodework:file" {
			// 保存文件
			handleMessageFile(content, false)
		} else if data["type"] == "nodework:cmd" {
			// 执行命令
			stdout, stderr, err := handleMessageCmd(content, data["log"] != "no")
			if data["callback"] != nil {
				cmderr := ""
				if err != nil {
					cmderr = err.Error()
				}
				err = ws.SendTextMessage(fmt.Sprintf(`{"type":"node","action":"cmd","callback":"%s","data":{"stdout":"%s","stderr":"%s","err":"%s"}}`, data["callback"], Base64Encode(stdout), Base64Encode(stderr), Base64Encode(cmderr)))
				if err != nil {
					logger.Debug("Send cmd callback error: %s", err)
				}
			}
		}
	}
}

// 保存文件或运行文件
func handleMessageFile(data string, force bool) {
	var err error
	files := strings.Split(data, ",")
	for _, file := range files {
		arr := strings.Split(file, ":")
		if arr[0] == "" {
			continue
		}
		//
		fileContent := ""
		fileName := ""
		if strings.HasPrefix(arr[0], "/") {
			fileName = arr[0]
		} else {
			fileName = fmt.Sprintf("%s/%s", workDir, arr[0])
		}
		fileDir := filepath.Dir(fileName)
		if !Exists(fileDir) {
			err = os.MkdirAll(fileDir, os.ModePerm)
			if err != nil {
				logger.Error("Mkdir error: [%s] %s", fileDir, err)
				continue
			}
		}
		if len(arr) > 2 {
			fileContent = Base64Decode(arr[2])
		} else {
			fileContent = Base64Decode(arr[1])
		}
		if fileContent == "" {
			logger.Warn("File empty: %s", fileName)
			continue
		}
		//
		fileKey := StringMd5(fileName)
		contentKey := StringMd5(fileContent)
		if !force {
			md5Value, _ := FileMd5.Load(fileKey)
			if md5Value != nil && md5Value.(string) == contentKey {
				logger.Debug("File same: %s", fileName)
				continue
			}
		}
		FileMd5.Store(fileKey, contentKey)
		//
		var stderr string
		var fileByte = []byte(fileContent)
		err = ioutil.WriteFile(fileName, fileByte, 0666)
		if err != nil {
			logger.Error("WriteFile error: [%s] %s", fileName, err)
			continue
		}
		if arr[1] == "exec" {
			logger.Info("Exec file start: [%s]", fileName)
			_, _, _ = Command("-c", fmt.Sprintf("chmod +x %s", fileName))
			_, stderr, err = Command(fileName)
			if err != nil {
				logger.Error("Exec file error: [%s] %s %s", fileName, err, stderr)
				continue
			} else {
				logger.Info("Exec file success: [%s]", fileName)
			}
		} else if arr[1] == "yml" {
			logger.Info("Run yml start: [%s]", fileName)
			cmd := fmt.Sprintf("cd %s && docker-compose up -d --remove-orphans", fileDir)
			_, stderr, err = Command("-c", cmd)
			if err != nil {
				logger.Error("Run yml error: [%s] %s %s", fileName, err, stderr)
				continue
			} else {
				logger.Info("Run yml success: [%s]", fileName)
			}
		} else if arr[1] == "nginx" {
			logger.Info("Run nginx start: [%s]", fileName)
			_, stderr, err = Command("-c", "nginx -s reload")
			if err != nil {
				logger.Error("Run nginx error: [%s] %s %s", fileName, err, stderr)
				continue
			} else {
				logger.Info("Run nginx success: [%s]", fileName)
			}
		} else if arr[1] == "danted" {
			program := fmt.Sprintf("danted -f %s", fileName)
			killPsef(program)
			time.Sleep(1 * time.Second)
			logger.Info("Run danted start: [%s]", fileName)
			cmd := fmt.Sprintf("%s > /dev/null 2>&1 &", program)
			_, stderr, err = Command("-c", cmd)
			if err != nil {
				logger.Error("Run danted error: [%s] %s %s", fileName, err, stderr)
				continue
			} else {
				logger.Info("Run danted success: [%s]", fileName)
				daemonStart(program, file)
			}
		} else if arr[1] == "xray" {
			program := fmt.Sprintf("%s/xray run -c %s", binDir, fileName)
			killPsef(program)
			time.Sleep(1 * time.Second)
			logger.Info("Run xray start: [%s]", fileName)
			cmd := fmt.Sprintf("%s > /dev/null 2>&1 &", program)
			_, stderr, err = Command("-c", cmd)
			if err != nil {
				logger.Error("Run xray error: [%s] %s %s", fileName, err, stderr)
				continue
			} else {
				logger.Info("Run xray success: [%s]", fileName)
				daemonStart(program, file)
			}
		}
	}
}

// 运行自定义脚本
func handleMessageCmd(cmd string, addLog bool) (string, string, error) {
	stdout, stderr, err := Command("-c", cmd)
	if addLog {
		if err != nil {
			logger.Error("Run cmd error: [%s] %s; stdout: [%s]; stderr: [%s]", cmd, err, stdout, stderr)
		} else {
			logger.Info("Run cmd success: [%s]", cmd)
		}
	}
	return stdout, stderr, err
}

// 杀死根据 ps -ef 查出来的
func killPsef(value string) {
	cmd := fmt.Sprintf("ps -ef | grep '%s' | grep -v 'grep' | awk '{print $2}'", value)
	result, _, _ := Command("-c", cmd)
	if len(result) > 0 {
		sc := bufio.NewScanner(strings.NewReader(result))
		for sc.Scan() {
			if len(sc.Text()) > 0 {
				_, _, _ = Command("-c", fmt.Sprintf("kill -9 %s", sc.Text()))
			}
		}
	}
}

// 守护进程
func daemonStart(value string, file string) {
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
				result, _, _ := Command("-c", cmd)
				if len(result) == 0 {
					handleMessageFile(file, true)
					return
				}
			}
		}
	}()
}
