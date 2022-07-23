package run

import (
	"fmt"
	"github.com/innet8/hios/pkg/logger"
	"github.com/togettoyou/wsc"
	"os"
	"time"
)

var (
	connectRand string
	logDir      = "/usr/lib/hicloud/log"
)

// BuildWork is
func BuildWork() {
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

// 定时任务A（上报：系统状态、入口网速）
func timedTaskA(ws *wsc.Wsc) error {
	return nil
}

// 定时任务B（上报：ping结果、流量统计）
func timedTaskB(ws *wsc.Wsc) error {
	return nil
}

// 处理消息
func handleMessageReceived(ws *wsc.Wsc, message string) {

}
