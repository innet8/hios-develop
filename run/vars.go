package run

import (
	"github.com/innet8/hios/pkg/sshcmd/sshutil"
	"sync"
	"time"
)

type ExecJson struct {
	Host      string
	Cmd       string
	Url       string
	SSHConfig sshutil.SSH
}

type RsaJson struct {
	Public  string
	Private string
}

type State struct {
	T   time.Time
	Cpu float64
	Mem struct {
		Current uint64
		Total   uint64
	}
	Swap struct {
		Current uint64
		Total   uint64
	}
	Disk struct {
		Current uint64
		Total   uint64
	}
	Uptime   uint64
	Loads    []float64
	TcpCount int
	UdpCount int
	NetIO    struct {
		Up   uint64
		Down uint64
	}
	NetTraffic struct {
		Sent uint64
		Recv uint64
	}
}

type NetIoNic struct {
	T    time.Time
	Up   uint64
	Down uint64
	Sent uint64
	Recv uint64
}

var (
	ExecConf ExecJson
	RsaConf  RsaJson
	FileMd5  sync.Map
)
