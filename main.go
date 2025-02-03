//go:generate go run generate.go

package main

import (
	"friis/loader"
)

func main() {
	loader.CreateProcess()
	loader.ReflectiveDLLInjection()
}
