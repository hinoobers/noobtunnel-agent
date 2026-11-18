//go:build windows

package main

import "github.com/hinoobers/noobtunnel-agent/internal/wg"

func newWindowsBackend() wg.Backend { return &wg.WindowsBackend{} }
