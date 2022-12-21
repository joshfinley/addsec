package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/joshfinly/addsec/src/addsec"
)

func main() {
	// Define flags for the source and target files.
	source := flag.String("s", "", "the source file with data to add to the new section")
	target := flag.String("t", "", "the target file to add a new section to")
	backdoor := flag.Bool("b", false,
		"backdoor the target (modify the entrypoint to point to the new section")

	// Parse the command-line arguments.
	flag.Parse()

	// Check if the source and target flags have been set.
	if *source == "" || *target == "" {
		fmt.Println("error: both the source and target flags are required")
		flag.PrintDefaults()
		return
	}

	// Read the file into a byte slice.
	data, err := ioutil.ReadFile(*source)
	if err != nil {
		fmt.Println(err)
		return
	}

	addsec.AddSection(*target, uint32(len(data)), data, *backdoor)

}
