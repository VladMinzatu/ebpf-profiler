package symbolizer

import (
	"bufio"
	"log/slog"
	"os"
)

type DataLoader struct {
	Path string
}

func NewDataLoader(path string) *DataLoader {
	return &DataLoader{Path: path}
}

func (d *DataLoader) ReadLines() ([]string, error) {
	slog.Debug("Loading lines from (pseudo-)file", "path", d.Path)
	f, err := os.Open(d.Path)
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
