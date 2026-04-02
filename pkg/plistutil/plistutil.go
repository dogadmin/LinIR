package plistutil

import (
	"fmt"
	"os"

	"howett.net/plist"
)

// LaunchItem represents a parsed LaunchAgent/LaunchDaemon plist.
type LaunchItem struct {
	Label                 string      `plist:"Label"`
	ProgramArguments      []string    `plist:"ProgramArguments"`
	Program               string      `plist:"Program"`
	RunAtLoad             bool        `plist:"RunAtLoad"`
	KeepAlive             interface{} `plist:"KeepAlive"` // can be bool or dict
	Disabled              bool        `plist:"Disabled"`
	UserName              string      `plist:"UserName"`
	WatchPaths            []string    `plist:"WatchPaths"`
	StartInterval         int         `plist:"StartInterval"`
	StartCalendarInterval interface{} `plist:"StartCalendarInterval"` // can be dict or array of dicts
}

// ParseLaunchPlist parses a LaunchAgent/LaunchDaemon plist file.
func ParseLaunchPlist(path string) (*LaunchItem, error) {
	item := &LaunchItem{}
	if err := ParsePlistFile(path, item); err != nil {
		return nil, err
	}
	return item, nil
}

// ParsePlistFile parses any plist file into the provided Go value.
func ParsePlistFile(path string, v interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("plistutil: open %s: %w", path, err)
	}
	defer f.Close()

	decoder := plist.NewDecoder(f)
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("plistutil: decode %s: %w", path, err)
	}
	return nil
}

// GetCommand extracts the effective command from a LaunchItem.
func GetCommand(item *LaunchItem) string {
	if item.Program != "" {
		return item.Program
	}
	if len(item.ProgramArguments) > 0 {
		return item.ProgramArguments[0]
	}
	return ""
}
