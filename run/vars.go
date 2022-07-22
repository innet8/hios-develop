package run

type InJson struct {
	Token  string
	Mtu    string
	Server string
	Swap   string
	Reset  bool
}

var (
	InConf InJson
)
