package addsec_test

import (
	"testing"

	"github.com/joshfinly/addsec/src/addsec"
)

func TestAddSection(t *testing.T) {
	newSecData := []byte{'a', 's', 'd', 'f'}
	addsec.AddSection("./calc.exe", "new_sec", 4, newSecData)
}
