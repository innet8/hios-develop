package run

import (
	"bytes"
	"fmt"
	"github.com/innet8/hios/pkg/xrsa"
	"os"
)

//BuildRsa is
func BuildRsa() {
	publicKey := bytes.NewBufferString("")
	privateKey := bytes.NewBufferString("")
	err := xrsa.CreateKeys(publicKey, privateKey, 2048)
	if err != nil {
		PrintError(fmt.Sprintf("Create error: %s", err))
		os.Exit(0)
	}
	WriteFile(fmt.Sprintf("%spublic", RsaConf.Path), publicKey.String())
	WriteFile(fmt.Sprintf("%sprivate", RsaConf.Path), privateKey.String())
}
