//go:build windows

package main

import (
	"os"
	"time"
)

func restartProcess() {
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(1)
	}()
}
