package symbolizer

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

type MapRegion struct {
	Start, End uint64
	Offset     uint64
	Perms      string
	Path       string
}

type MapsReader interface {
	ReadLines() ([]string, error)
}

type ProcMapsReader struct {
	loader *DataLoader
}

func NewProcMapsReader(pid int) *ProcMapsReader {
	return &ProcMapsReader{&DataLoader{Path: fmt.Sprintf("/proc/%d/map", pid)}}
}

func (p *ProcMapsReader) ReadLines() ([]string, error) {
	return p.loader.ReadLines()
}

type procMaps struct {
	mapReader MapsReader
	regions   []MapRegion
}

func NewProcMaps(mapReader MapsReader) (*procMaps, error) {
	p := &procMaps{mapReader: mapReader}
	err := p.Refresh()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// TODO: maps should be in order so we could optimize to a binary search or use a tree
func (m *procMaps) FindRegion(pc uint64) *MapRegion {
	for _, r := range m.regions {
		if pc >= r.Start && pc < r.End {
			return &r
		}
	}
	return nil
}

func (m *procMaps) Refresh() error {
	lines, err := m.mapReader.ReadLines()
	if err != nil {
		return err
	}
	return m.parseMaps(lines)
}

func (m *procMaps) parseMaps(lines []string) error {
	var regions []MapRegion
	for _, line := range lines {
		if line == "" {
			continue
		}
		entry, err := parseMapEntry(line)
		if err != nil {
			slog.Warn("Failed to parse map entry", "line", line, "error", err)
			continue
		}
		regions = append(regions, entry)
	}
	m.regions = regions
	return nil
}

// Example format:
//
//	55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog
func parseMapEntry(line string) (MapRegion, error) {
	parts := strings.Fields(line)
	if len(parts) < 5 {
		return MapRegion{}, fmt.Errorf("not enough fields: %d in line \"%s\"", len(parts), line)
	}
	addr := parts[0]
	perms := parts[1]
	off := parts[2]
	// pathname is optional and may be in parts[5:] - may contain spaces, mind you!
	var path string
	if len(parts) >= 6 {
		path = strings.Join(parts[5:], " ")
	}
	se := strings.SplitN(addr, "-", 2)
	if len(se) != 2 {
		return MapRegion{}, fmt.Errorf("invalid address range format in line %s", line)
	}
	start, err1 := strconv.ParseUint(se[0], 16, 64)
	end, err2 := strconv.ParseUint(se[1], 16, 64)
	offv, err3 := strconv.ParseUint(off, 16, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return MapRegion{}, fmt.Errorf("failed to parse numeric addresses in line %s", line)
	}
	return MapRegion{Start: start, End: end, Offset: offv, Perms: perms, Path: path}, nil
}
