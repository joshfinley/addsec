package addsec_test

import (
	"testing"

	"github.com/joshfinly/addsec/src/addsec"
)

func TestAddSection(t *testing.T) {
	newSecData := make([]byte, 1024)
	addsec.AddSection("./calc.exe", 1024, newSecData)
}
