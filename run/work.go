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
	"math"
	"net"
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
	monitorRand string

	configUpdating bool
	configContinue string

	ws         *wsc.Wsc
	hostState  *State
	netIoInNic *NetIoNic

	costMap    = make(map[string]*costModel)
	monitorMap = make(map[string]*monitorModel)
	pingMap    = make(map[string]float64)
	dantedMap  = make(map[string]string)
	xrayMap    = make(map[string]string)
	daemonMap  = make(map[string]string)
)

type msgModel struct {
	Type    string    `json:"type"`
	Content string    `json:"content"`
	File    fileModel `json:"file"`
	Cmd     cmdModel  `json:"cmd"`
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

type callModel struct {
	Callback string `json:"callback"`
	Output   string `json:"output"`
	Err      string `json:"err"`
}

type costModel struct {
	Interface string
	Ip        string
	Cost      int
}

type monitorModel struct {
	State string
	Ping  float64
	Unix  int64
}

// WorkStart Work开始
func WorkStart() {
	_ = logger.SetLogger(`{"File":{"filename":"/usr/lib/hicloud/log/work.log","level":"TRAC","daily":true,"maxlines":100000,"maxsize":10,"maxdays":3,"append":true,"permit":"0660"}}`)
	//
	if !Exists(fmt.Sprintf("%s/server_public", sshDir)) {
		logger.Error("[start] server public key does not exist")
		os.Exit(1)
	}
	if !Exists(fmt.Sprintf("%s/node_public", sshDir)) {
		logger.Error("[start] node public key does not exist")
		os.Exit(1)
	}
	if !Exists(fmt.Sprintf("%s/node_private", sshDir)) {
		logger.Error("[start] node private key does not exist")
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
		logger.Error(fmt.Sprintf("[start] failed to create log dir: %s\n", err.Error()))
		os.Exit(1)
	}
	startRun()
	//
	done := make(chan bool)
	ws = wsc.New(wsUrl)
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
		logger.Debug("[ws] connected: ", ws.WebSocket.Url)
		logger.SetWebsocket(ws)
		onConnected()
	})
	ws.OnConnectError(func(err error) {
		logger.Debug("[ws] connect error: ", err.Error())
	})
	ws.OnDisconnected(func(err error) {
		logger.Debug("[ws] disconnected: ", err.Error())
	})
	ws.OnClose(func(code int, text string) {
		logger.Debug("[ws] close: ", code, text)
		done <- true
	})
	ws.OnTextMessageSent(func(message string) {
		if !strings.HasPrefix(message, "r:") {
			logger.Debug("[ws] text message sent: ", message)
		}
	})
	ws.OnBinaryMessageSent(func(data []byte) {
		logger.Debug("[ws] binary message sent: ", string(data))
	})
	ws.OnSentError(func(err error) {
		logger.Debug("[ws] sent error: ", err.Error())
	})
	ws.OnPingReceived(func(appData string) {
		logger.Debug("[ws] ping received: ", appData)
	})
	ws.OnPongReceived(func(appData string) {
		logger.Debug("[ws] pong received: ", appData)
	})
	ws.OnTextMessageReceived(func(message string) {
		if strings.HasPrefix(message, "r:") {
			message = xrsa.Decrypt(message[2:], nodePublic, nodePrivate) // 判断数据解密
		} else {
			logger.Debug("[ws] text message received: ", message)
		}
		handleMessageReceived(message)
	})
	ws.OnBinaryMessageReceived(func(data []byte) {
		logger.Debug("[ws] binary message received: ", string(data))
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
func onConnected() {
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
				err := timedTaskA()
				if err != nil {
					logger.Debug("[timed] task A: %s", err)
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
				err := timedTaskB()
				if err != nil {
					logger.Debug("[timed] task B: %s", err)
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
		logger.Error("[start] error: %s", err)
	}
	for i := range files {
		file := files[i]
		content := ReadFile(file)
		_, _ = Cmd("-c", content)
	}
}

// 定时任务A（上报：系统状态、入口网速）
func timedTaskA() error {
	hiMode := os.Getenv("HI_MODE")
	sendMessage := ""
	if hiMode == "host" {
		hostState = GetHostState(hostState)
		if hostState != nil {
			value, err := json.Marshal(hostState)
			if err != nil {
				logger.Error("[state] host error: %s", err)
			} else {
				sendMessage = formatSendMsg("state", string(value))
			}
		}
	} else if hiMode == "hihub" {
		netIoInNic = GetNetIoInNic(netIoInNic)
		if netIoInNic != nil {
			value, err := json.Marshal(netIoInNic)
			if err != nil {
				logger.Error("[netio] in nic error: %s", err)
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

// 定时任务B（上报：ping、检查xray、流量统计）
func timedTaskB() error {
	hiMode := os.Getenv("HI_MODE")
	sendMessage := ""
	if hiMode == "hihub" {
		// 公网 ping
		sendErr := pingSend(fmt.Sprintf("%s/ips", workDir))
		if sendErr != nil {
			return sendErr
		}
		// 对端 ping
		go pingPPP()
		// todo wg 流量统计
	} else {
		// 发送刷新
		sendMessage = formatSendMsg("refresh", time.Now().Unix())
	}
	if sendMessage != "" {
		return ws.SendTextMessage(sendMessage)
	}
	return nil
}

// ping 对端并更新对端cost值
func pingPPP() {
	pppFile := fmt.Sprintf("%s/pppip", workDir)
	if !Exists(pppFile) {
		return
	}
	logger.Debug("[ppp] start ping")
	_, err := pingFile(pppFile, "")
	if err != nil {
		logger.Debug("[ppp] ping error: %s", err)
		return
	}
	costContent := ""
	for ip, model := range costMap {
		cost := int(math.Ceil(pingMap[ip]))
		if cost == 0 || cost > 9999 {
			cost = 9999
		}
		diff := math.Abs(float64(model.Cost - cost))
		update := false
		if cost <= 10 {
			update = diff >= 2 // ping值相差≥2
		} else if cost <= 100 {
			update = diff >= 5 // ping值相差≥5
		} else if cost <= 200 {
			update = diff >= 10 // ping值相差≥10
		} else {
			update = diff >= 20 // ping值相差≥20
		}
		if update {
			model.Cost = cost
			costMap[ip] = model
			costContent = fmt.Sprintf("%s\nset protocols ospf interface %s cost %d", costContent, model.Interface, model.Cost)
		}
	}
	if len(costContent) == 0 {
		return
	}
	costFile := fmt.Sprintf("%s/cost", binDir)
	costContent = fmt.Sprintf("#!/bin/vbash\nsource /opt/vyatta/etc/functions/script-template\n%s\ncommit\nexit", costContent)
	err = ioutil.WriteFile(costFile, []byte(costContent), 0666)
	if err != nil {
		logger.Error("[cost] write file error: %s", err)
		return
	}
	_, _ = Cmd("-c", fmt.Sprintf("chmod +x %s", costFile))
	cmdRes, cmdErr := Command(costFile)
	if cmdErr != nil {
		logger.Error("[cost] set error: %s %s", cmdRes, cmdErr)
	} else {
		logger.Debug("[cost] set success")
	}
}

// ping 文件并发送
func pingSend(fileName string) error {
	if !Exists(fileName) {
		return nil
	}
	logger.Debug("[ping] start '%s'", fileName)
	result, err := pingFile(fileName, "")
	if err != nil {
		logger.Debug("[ping] error '%s': %s", fileName, err)
		return nil
	}
	sendMessage := formatSendMsg("ping", result)
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
	var resMap = make(map[string]float64)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		s := spaceRe.Split(scanner.Text(), -1)
		if len(s) > 9 {
			float, _ := strconv.ParseFloat(s[9], 64)
			resMap[s[0]] = float
		} else {
			resMap[s[0]] = 0
		}
		pingMap[s[0]] = resMap[s[0]]
	}
	return resMap, nil
}

// 处理消息
func handleMessageReceived(message string) {
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
					logger.Debug("[cmd] send callback error: %s", err)
				}
			}
		} else if data.Type == "monitorip" {
			// 监听ip状态
			monitorRand = RandString(6)
			go handleMessageMonitorIp(monitorRand, data.Content)
		}
	}
}

// 保存文件或运行文件
func handleMessageFile(fileData fileModel, force bool) {
	var err error
	if !strings.HasPrefix(fileData.Path, "/") {
		fileData.Path = fmt.Sprintf("%s/%s", workDir, fileData.Path)
	}
	fileDir := filepath.Dir(fileData.Path)
	if !Exists(fileDir) {
		err = os.MkdirAll(fileDir, os.ModePerm)
		if err != nil {
			logger.Error("[file] mkdir error: '%s' %s", fileDir, err)
			return
		}
	}
	fileContent := fileData.Content
	if fileContent == "" {
		logger.Warn("[file] empty: %s", fileData.Path)
		return
	}
	//
	fileKey := StringMd5(fileData.Path)
	contentKey := StringMd5(fileContent)
	if !force {
		md5Value, _ := FileMd5.Load(fileKey)
		if md5Value != nil && md5Value.(string) == contentKey {
			logger.Debug("[file] same: %s", fileData.Path)
			return
		}
	}
	FileMd5.Store(fileKey, contentKey)
	//
	if fileData.Type == "configure" {
		fileContent = convertConfigure(fileContent)
	}
	//
	var output string
	err = ioutil.WriteFile(fileData.Path, []byte(fileContent), 0666)
	if err != nil {
		logger.Error("[file] write error: '%s' %s", fileData.Path, err)
		return
	}
	if InArray(fileData.Type, []string{"bash", "cmd", "exec"}) {
		logger.Info("[bash] start: '%s'", fileData.Path)
		_, _ = Bash("-c", fmt.Sprintf("chmod +x %s", fileData.Path))
		output, err = Bash(fileData.Path)
		if err != nil {
			logger.Error("[bash] error: '%s' %s %s", fileData.Path, err, output)
		} else {
			logger.Info("[bash] success: '%s'", fileData.Path)
		}
	} else if fileData.Type == "sh" {
		logger.Info("[sh] start: '%s'", fileData.Path)
		_, _ = Cmd("-c", fmt.Sprintf("chmod +x %s", fileData.Path))
		output, err = Cmd(fileData.Path)
		if err != nil {
			logger.Error("[sh] error: '%s' %s %s", fileData.Path, err, output)
		} else {
			logger.Info("[sh] success: '%s'", fileData.Path)
		}
	} else if fileData.Type == "yml" {
		logger.Info("[yml] start: '%s'", fileData.Path)
		cmd := fmt.Sprintf("cd %s && docker-compose up -d --remove-orphans", fileDir)
		output, err = Cmd("-c", cmd)
		if err != nil {
			logger.Error("[yml] error: '%s' %s %s", fileData.Path, err, output)
		} else {
			logger.Info("[yml] success: '%s'", fileData.Path)
		}
	} else if fileData.Type == "nginx" {
		logger.Info("[nginx] start: '%s'", fileData.Path)
		output, err = Cmd("-c", "nginx -s reload")
		if err != nil {
			logger.Error("[nginx] error: '%s' %s %s", fileData.Path, err, output)
		} else {
			logger.Info("[nginx] success: '%s'", fileData.Path)
		}
	} else if fileData.Type == "configure" {
		loadConfigure(fileData.Path, 0)
	} else if fileData.Type == "danted" {
		loadDanted(fileData)
	} else if fileData.Type == "xray" {
		loadXray(fileData)
	}
}

// 运行自定义脚本
func handleMessageCmd(cmd string, addLog bool) (string, error) {
	output, err := Cmd("-c", cmd)
	if addLog {
		if err != nil {
			logger.Error("[cmd] error: '%s' %s; output: '%s'", cmd, err, output)
		} else {
			logger.Info("[cmd] success: '%s'", cmd)
		}
	}
	return output, err
}

// 监听ip通或不通上报（ping值变化超过5也上报）
func handleMessageMonitorIp(rand string, content string) {
	var fileText []string
	array := strings.Split(content, ",")
	for _, value := range array {
		arr := strings.Split(value, ":")
		address := net.ParseIP(arr[0])
		if address == nil {
			continue
		}
		ip := address.String()
		if len(arr) >= 4 {
			state := arr[1]
			ping, _ := strconv.ParseFloat(arr[2], 64)
			unix, _ := strconv.ParseInt(arr[3], 10, 64)
			monitorMap[ip] = &monitorModel{State: state, Ping: ping, Unix: unix}
		}
		fileText = append(fileText, ip)
	}
	fileName := fmt.Sprintf("%s/monitorip_%s.txt", workDir, rand)
	err := ioutil.WriteFile(fileName, []byte(strings.Join(fileText, "\n")), 0666)
	if err != nil {
		logger.Error("[monitorip] '%s' write file error: '%s' %s", rand, fileName, err)
		return
	}
	//
	for {
		if rand != monitorRand {
			_ = os.Remove(fileName)
			logger.Debug("[monitorip] '%s' jump thread", rand)
			return
		}
		result, pingErr := pingFileMap(fileName, "", 2000, 4)
		if pingErr != nil {
			logger.Debug("[monitorip] '%s' ping error: %s", rand, pingErr)
			time.Sleep(2 * time.Second)
			continue
		}
		var state string
		var record *monitorModel
		var report = make(map[string]*monitorModel)
		var unix = time.Now().Unix()
		for ip, ping := range result {
			state = "reject"
			if ping > 0 {
				state = "accept" // ping值大于0表示线路通
			}
			record = monitorMap[ip]
			/**
			1、记录没有
			2、状态改变（通 不通 发生改变）
			3、大于10分钟
			4、大于10秒钟且（与上次ping值相差大于等于50或与上次相差1.1倍）
			*/
			if record == nil || record.State != state || unix-record.Unix >= 600 || (unix-record.Unix >= 10 && computePing(record.Ping, ping)) {
				report[ip] = &monitorModel{State: state, Ping: ping, Unix: unix}
				monitorMap[ip] = report[ip]
			}
		}
		if len(report) > 0 {
			reportValue, jsonErr := json.Marshal(report)
			if jsonErr != nil {
				logger.Debug("[monitorip] '%s' marshal error: %s", rand, jsonErr)
				for ip := range report {
					delete(monitorMap, ip)
				}
			} else {
				sendMessage := formatSendMsg("monitorip", string(reportValue))
				sendErr := ws.SendTextMessage(sendMessage)
				if sendErr != nil {
					logger.Debug("[monitorip] '%s' send error: %s", rand, sendErr)
					for ip := range report {
						delete(monitorMap, ip)
					}
				}
			}
		}
	}
}

// 转换配置内容
func convertConfigure(config string) string {
	pppIp := ""
	costMap = make(map[string]*costModel)
	rege, err := regexp.Compile(`//\s*interface\s+(wg\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+cost`)
	if err == nil {
		config = rege.ReplaceAllStringFunc(config, func(value string) string {
			match := rege.FindStringSubmatch(value)
			model := &costModel{
				Interface: match[1],
				Ip:        match[2],
				Cost:      int(math.Ceil(pingMap[match[2]])),
			}
			if model.Cost == 0 || model.Cost > 9999 {
				model.Cost = 9999
			}
			costMap[model.Ip] = model
			pppIp = fmt.Sprintf("%s\n%s", pppIp, model.Ip)
			return fmt.Sprintf(`interface %s {
            cost %d
         }`, model.Interface, model.Cost) // 注意保留换行缩进
		})
	}
	pppFile := fmt.Sprintf("%s/pppip", workDir)
	if len(pppIp) > 0 {
		WriteFile(pppFile, strings.TrimSpace(pppIp))
	} else {
		_ = os.Remove(pppFile)
	}
	return fmt.Sprintf("%s\n%s", config, `// vyos-config-version: "bgp@2:broadcast-relay@1:cluster@1:config-management@1:conntrack@3:conntrack-sync@2:dhcp-relay@2:dhcp-server@6:dhcpv6-server@1:dns-forwarding@3:firewall@7:flow-accounting@1:https@3:interfaces@26:ipoe-server@1:ipsec@9:isis@1:l2tp@4:lldp@1:mdns@1:monitoring@1:nat@5:nat66@1:ntp@1:openconnect@2:ospf@1:policy@3:pppoe-server@5:pptp@2:qos@1:quagga@10:rpki@1:salt@1:snmp@2:ssh@2:sstp@4:system@25:vrf@3:vrrp@3:vyos-accel-ppp@2:wanloadbalance@3:webproxy@2"`)
}

// 加载configure
func loadConfigure(fileName string, againNum int) {
	if configUpdating {
		logger.Info("[configure] wait: '%s'", fileName)
		configContinue = fileName
		return
	}
	configContinue = ""
	configUpdating = true
	//
	go func() {
		logger.Info("[configure] start: '%s'", fileName)
		ch := make(chan int)
		var err error
		go func() {
			cmd := fmt.Sprintf("%s/entrypoint.sh config %s", binDir, fileName)
			_, err = Command("-c", cmd)
			ch <- 1
		}()
		select {
		case <-ch:
			if err != nil {
				logger.Error("[configure] error: '%s' %s", fileName, err)
			} else {
				logger.Info("[configure] success: '%s'", fileName)
			}
		case <-time.After(time.Second * 180):
			logger.Error("[configure] timeout: '%s'", fileName)
			err = errors.New("timeout")
		}
		if err != nil {
			time.Sleep(10 * time.Second)
		}
		configUpdating = false
		if len(configContinue) > 0 {
			logger.Info("[configure] continue: '%s'", configContinue)
			loadConfigure(configContinue, 0)
		} else if err != nil && againNum < 10 {
			againNum = againNum + 1
			logger.Info("[configure] again: '%s' take %d", fileName, againNum)
			loadConfigure(fileName, againNum)
		}
	}()
}

// 加载danted
func loadDanted(fileData fileModel) {
	key := StringMd5(fileData.Path)
	rand := RandString(6)
	dantedMap[key] = rand
	go func() {
		for {
			if rand != dantedMap[key] {
				logger.Debug("[danted] jump: '%s'", fileData.Path)
				break
			}
			res, _ := Cmd("-c", "wg")
			if len(res) == 0 {
				logger.Debug("[danted] wait wireguard: '%s'", fileData.Path)
				time.Sleep(10 * time.Second)
				continue
			}
			//
			content := fmt.Sprintf("danted -f %s", fileData.Path)
			killPsef(content)
			time.Sleep(1 * time.Second)
			logger.Info("[danted] start: '%s'", fileData.Path)
			cmd := fmt.Sprintf("%s > /dev/null 2>&1 &", content)
			output, err := Cmd("-c", cmd)
			if err != nil {
				logger.Error("[danted] error: '%s' %s %s", fileData.Path, err, output)
			} else {
				logger.Info("[danted] success: '%s'", fileData.Path)
				daemonPsef(content, fileData)
			}
			break
		}
	}()
}

// 加载xray
func loadXray(fileData fileModel) {
	key := StringMd5(fileData.Path)
	rand := RandString(6)
	xrayMap[key] = rand
	go func() {
		for {
			if rand != xrayMap[key] {
				logger.Debug("[xray] jump: '%s'", fileData.Path)
				break
			}
			res, _ := Cmd("-c", "wg")
			if len(res) == 0 {
				logger.Debug("[xray] wait wireguard: '%s'", fileData.Path)
				time.Sleep(10 * time.Second)
				continue
			}
			//
			content := fmt.Sprintf("%s/xray run -c %s", binDir, fileData.Path)
			killPsef(content)
			time.Sleep(1 * time.Second)
			logger.Info("[xray] start: '%s'", fileData.Path)
			cmd := fmt.Sprintf("%s > /dev/null 2>&1 &", content)
			output, err := Cmd("-c", cmd)
			if err != nil {
				logger.Error("[xray] error: '%s' %s %s", fileData.Path, err, output)
			} else {
				logger.Info("[xray] success: '%s'", fileData.Path)
				daemonPsef(content, fileData)
			}
			break
		}
	}()
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

// 计算对比ping值
func computePing(var1, var2 float64) bool {
	diff := math.Abs(var1 - var2)
	if diff < 5 {
		return false
	}
	if diff >= 50 {
		return true
	}
	var multiple float64
	if var1 > var2 {
		multiple = var1 / var2
	} else {
		multiple = var2 / var1
	}
	if multiple < 1.1 {
		return false
	}
	return true
}

// 杀死根据 ps -ef 查出来的
func killPsef(content string) {
	cmd := fmt.Sprintf("ps -ef | grep '%s' | grep -v 'grep' | awk '{print $2}'", content)
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

// 守护进程根据 ps -ef 查出来的
func daemonPsef(content string, fileData fileModel) {
	key := StringMd5(content)
	rand := RandString(6)
	daemonMap[key] = rand
	go func() {
		// 每10秒检测一次
		t := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-t.C:
				if rand != daemonMap[key] {
					logger.Debug("[daemon] jump: '%s'", content)
					return
				}
				if !Exists(fileData.Path) {
					logger.Debug("[daemon] stop: '%s'", content)
					killPsef(content)
					return
				}
				cmd := fmt.Sprintf("ps -ef | grep '%s' | grep -v 'grep'", content)
				output, _ := Cmd("-c", cmd)
				if len(output) == 0 {
					logger.Error("[daemon] lose: '%s'", content)
					handleMessageFile(fileData, true)
					return
				}
			}
		}
	}()
}
