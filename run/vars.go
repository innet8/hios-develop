package run

type InJson struct {
	Token  string
	Mtu    string
	Server string
	Swap   string
	Iver   string
	Reset  bool
}

var (
	InConf InJson
)
