package machoutil

import (
	"debug/macho"
	"fmt"
)

// MachOInfo contains forensic-relevant Mach-O metadata extracted via debug/macho.
type MachOInfo struct {
	IsMachO    bool     `json:"is_macho"`
	CPU        string   `json:"cpu,omitempty"`
	Type       string   `json:"type,omitempty"`
	IsStripped bool     `json:"is_stripped"`
	IsFat      bool     `json:"is_fat"`
	Imports    []string `json:"imports,omitempty"`
	HasCodeSig bool     `json:"has_code_sig"`
}

// Analyze opens the file at path and extracts forensic-relevant Mach-O metadata.
func Analyze(path string) (*MachOInfo, error) {
	// Try fat binary first
	fat, fatErr := macho.OpenFat(path)
	if fatErr == nil {
		defer fat.Close()
		info := &MachOInfo{IsMachO: true, IsFat: true}
		if len(fat.Arches) > 0 {
			info.CPU = fat.Arches[0].Cpu.String()
			info.Type = fat.Arches[0].Type.String()
			fillMachODetails(fat.Arches[0].File, info)
		}
		return info, nil
	}

	f, err := macho.Open(path)
	if err != nil {
		return &MachOInfo{IsMachO: false}, nil
	}
	defer f.Close()

	info := &MachOInfo{
		IsMachO: true,
		CPU:     f.Cpu.String(),
		Type:    f.Type.String(),
	}
	fillMachODetails(f, info)
	return info, nil
}

func fillMachODetails(f *macho.File, info *MachOInfo) {
	if f.Symtab == nil {
		info.IsStripped = true
	}
	imports, err := f.ImportedLibraries()
	if err == nil {
		info.Imports = imports
	}
	// Check LC_CODE_SIGNATURE
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) >= 4 {
			cmd := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24
			if cmd == 29 {
				info.HasCodeSig = true
				break
			}
		}
	}
}

// FormatSummary returns a one-line summary.
func FormatSummary(info *MachOInfo) string {
	if !info.IsMachO {
		return "not Mach-O"
	}
	return fmt.Sprintf("Mach-O %s %s fat=%v stripped=%v codesig=%v imports=%d",
		info.Type, info.CPU, info.IsFat, info.IsStripped, info.HasCodeSig, len(info.Imports))
}
