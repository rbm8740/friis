package loader

import (
	"syscall"

	"friis/config"

	"golang.org/x/sys/windows"
)

func CreateProcess() *syscall.ProcessInformation {
	var startupInfo syscall.StartupInfo
	var processInfo syscall.ProcessInformation

	commandLine, err := syscall.UTF16PtrFromString(config.Target)

	if err != nil {
		return nil
	}

	err = syscall.CreateProcess(
		nil,
		commandLine,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&startupInfo,
		&processInfo)

	if err != nil {
		return nil
	}

	return &processInfo
}
