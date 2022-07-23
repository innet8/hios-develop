package run

type InJson struct {
	Token  string
	Mtu    string
	Server string
	Swap   string
	Iver   string
	Reset  bool
}

type WorkJson struct {
	Server string
}

var (
	InConf   InJson
	WorkConf WorkJson
)
