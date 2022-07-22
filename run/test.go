package run

import (
	"fmt"
	"github.com/innet8/hios/pkg/logger"
	"os"
	"path/filepath"
)

//BuildTest is
func BuildTest() {
	nodeMode := os.Getenv("NODE_MODE")
	logger.Debug("NODE_MODE: %s", nodeMode)

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	fmt.Println(exPath)
}
