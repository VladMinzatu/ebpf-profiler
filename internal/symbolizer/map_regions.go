package symbolizer

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type MapRegion struct {
	Start, End uint64
	Offset     uint64
	Perms      string
	Path       string
}

type MapRegions struct {
	regions []MapRegion
}

func ReadProcMaps(pid int) (*MapRegions, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var regions []MapRegion
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		entry, err := parseEntry(line)
		if err != nil {
			slog.Warn("Failed to parse entry in /proc/<pid>/map file", "pid", pid, "err", err)
			continue
		}
		regions = append(regions, entry)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return &MapRegions{regions: regions}, nil
}

func (m *MapRegions) FindRegion(ip uint64) *MapRegion {
	// TODO: maps should be in order so we could optimize to a binary search or use a tree
	for _, m := range m.regions {
		if ip >= m.Start && ip < m.End {
			return &m
		}
	}
	return nil
}

func parseEntry(line string) (MapRegion, error) {
	// example:
	// 55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog
	parts := strings.Fields(line)
	if len(parts) < 5 {
		return MapRegion{}, fmt.Errorf("not enough fields fields: %d in line \"%s\"", len(parts), line)
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
	start, err1 := strconv.ParseUint(se[0], 16, 64)
	end, err2 := strconv.ParseUint(se[1], 16, 64)
	offv, err3 := strconv.ParseUint(off, 16, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return MapRegion{}, fmt.Errorf("failed to parse numeric addresses in line %s", line)
	}
	return MapRegion{Start: start, End: end, Offset: offv, Perms: perms, Path: path}, nil
}
