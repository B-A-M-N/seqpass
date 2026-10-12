package security

import (
	"fmt"
	"os"
)

func myUID() string {
	return fmt.Sprintf("%d", os.Geteuid())
}

func myUIDNum() int {
	return os.Geteuid()
}
