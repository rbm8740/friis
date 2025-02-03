package config

import (
	"fmt"
	"log"
	"os"
)

// loadShellcode loads shellcode from a DLL file.
// Reads the contents of the specified DLL by caller and return it as a byte slice.
// This function assumes that the DLL is in the config/payloads/<module> directory and is named "<module>.dll".
func LoadShellcode(module string) []byte {
	fmt.Println()
	dllBytes, err := os.ReadFile("./config/payloads/" + module + "/" + module + ".dll")
	if err != nil {
		log.Fatalf("Failed to open file %v", err)
	}
	return dllBytes
}
