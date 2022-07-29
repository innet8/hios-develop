package run

import (
	"fmt"
	"github.com/innet8/hios/pkg/logger"
	"os"
	"path/filepath"
)

//BuildTest is
func BuildTest() {
	hiMode := os.Getenv("HI_MODE")
	logger.Debug("HI_MODE: %s", hiMode)

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	fmt.Println(exPath)
}
