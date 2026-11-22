//go:build !windows

package agent

func allowPublicRead(path string, directory bool) error { return nil }
