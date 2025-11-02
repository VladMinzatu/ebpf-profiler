package symbolizer

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
)

type ProcMapsReader struct{}

func NewProcMapsReader() *ProcMapsReader {
	return &ProcMapsReader{}
}

func (r *ProcMapsReader) ReadMaps(pid int) ([]string, error) {
	slog.Debug("Reading proc maps for pid", "pid", pid)
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
