package main

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func quickPlatformConfigDirs() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var dirs []string
	for index := 0; index < 26; index++ {
		if mask&(1<<index) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+index)
		path, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(path) != windows.DRIVE_FIXED {
			continue
		}
		for _, relative := range []string{"ProgramData\\noobtunnel", "Program Files\\noobtunnel", "noobtunnel"} {
			dirs = append(dirs, filepath.Join(root, relative))
		}
	}
	return dirs
}
