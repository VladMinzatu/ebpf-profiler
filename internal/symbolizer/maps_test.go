package symbolizer

import (
	"errors"
	"testing"
)

type mockMapsReader struct {
	lines []string
	err   error
}

func (m *mockMapsReader) ReadMaps(pid int) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.lines, nil
}

func TestParseMapEntry(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    MapRegion
		wantErr bool
	}{
		{
			name: "valid entry with path",
			line: "55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
			want: MapRegion{
				Start:  0x55d4b2000000,
				End:    0x55d4b2021000,
				Offset: 0x00000000,
				Perms:  "r--p",
				Path:   "/usr/bin/myprog",
			},
			wantErr: false,
		},
		{
			name: "valid entry without path",
			line: "7f8a9b000000-7f8a9b002000 r-xp 00001000 08:01 131074",
			want: MapRegion{
				Start:  0x7f8a9b000000,
				End:    0x7f8a9b002000,
				Offset: 0x00001000,
				Perms:  "r-xp",
				Path:   "",
			},
			wantErr: false,
		},
		{
			name: "valid entry with path containing spaces",
			line: "7f8a9b000000-7f8a9b002000 r-xp 00001000 08:01 131074 /usr/lib/libc.so.6 (deleted)",
			want: MapRegion{
				Start:  0x7f8a9b000000,
				End:    0x7f8a9b002000,
				Offset: 0x00001000,
				Perms:  "r-xp",
				Path:   "/usr/lib/libc.so.6 (deleted)",
			},
			wantErr: false,
		},
		{
			name:    "insufficient fields",
			line:    "55d4b2000000-55d4b2021000 r--p",
			wantErr: true,
		},
		{
			name:    "invalid address range format",
			line:    "55d4b2000000 r--p 00000000 08:01 131073 /usr/bin/myprog",
			wantErr: true,
		},
		{
			name:    "invalid hex address",
			line:    "invalid-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
			wantErr: true,
		},
		{
			name:    "empty line",
			line:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMapEntry(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMapEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Start != tt.want.Start {
					t.Errorf("parseMapEntry() Start = %x, want %x", got.Start, tt.want.Start)
				}
				if got.End != tt.want.End {
					t.Errorf("parseMapEntry() End = %x, want %x", got.End, tt.want.End)
				}
				if got.Offset != tt.want.Offset {
					t.Errorf("parseMapEntry() Offset = %x, want %x", got.Offset, tt.want.Offset)
				}
				if got.Perms != tt.want.Perms {
					t.Errorf("parseMapEntry() Perms = %q, want %q", got.Perms, tt.want.Perms)
				}
				if got.Path != tt.want.Path {
					t.Errorf("parseMapEntry() Path = %q, want %q", got.Path, tt.want.Path)
				}
			}
		})
	}
}

func TestNewProcMaps(t *testing.T) {
	tests := []struct {
		name    string
		pid     int
		reader  MapsReader
		wantErr bool
	}{
		{
			name: "valid maps",
			pid:  1234,
			reader: &mockMapsReader{
				lines: []string{
					"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
					"7f8a9b000000-7f8a9b002000 r-xp 00001000 08:01 131074 /usr/lib/libc.so.6",
				},
			},
			wantErr: false,
		},
		{
			name: "empty maps",
			pid:  1234,
			reader: &mockMapsReader{
				lines: []string{},
			},
			wantErr: false,
		},
		{
			name: "reader error",
			pid:  1234,
			reader: &mockMapsReader{
				err: errors.New("read error"),
			},
			wantErr: true,
		},
		{
			name: "invalid line skipped",
			pid:  1234,
			reader: &mockMapsReader{
				lines: []string{
					"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
					"invalid line",
					"7f8a9b000000-7f8a9b002000 r-xp 00001000 08:01 131074 /usr/lib/libc.so.6",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProcMaps(tt.pid, tt.reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProcMaps() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Error("NewProcMaps() returned nil on success")
			}
		})
	}
}

func TestProcMaps_FindRegion(t *testing.T) {
	reader := &mockMapsReader{
		lines: []string{
			"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
			"7f8a9b000000-7f8a9b002000 r-xp 00001000 08:01 131074 /usr/lib/libc.so.6",
			"7f8a9b100000-7f8a9b102000 rw-p 00002000 08:01 131075 [heap]",
		},
	}

	maps, err := NewProcMaps(1234, reader)
	if err != nil {
		t.Fatalf("NewProcMaps() error = %v", err)
	}

	tests := []struct {
		name    string
		pc      uint64
		want    *MapRegion
		wantNil bool
	}{
		{
			name: "find region in first mapping",
			pc:   0x55d4b2000100,
			want: &MapRegion{
				Start:  0x55d4b2000000,
				End:    0x55d4b2021000,
				Offset: 0x00000000,
				Perms:  "r--p",
				Path:   "/usr/bin/myprog",
			},
			wantNil: false,
		},
		{
			name: "find region at start boundary",
			pc:   0x55d4b2000000,
			want: &MapRegion{
				Start: 0x55d4b2000000,
				End:   0x55d4b2021000,
				Perms: "r--p",
				Path:  "/usr/bin/myprog",
			},
			wantNil: false,
		},
		{
			name: "find region just before end",
			pc:   0x55d4b2020fff,
			want: &MapRegion{
				Start: 0x55d4b2000000,
				End:   0x55d4b2021000,
				Perms: "r--p",
				Path:  "/usr/bin/myprog",
			},
			wantNil: false,
		},
		{
			name: "find region in second mapping",
			pc:   0x7f8a9b000100,
			want: &MapRegion{
				Start:  0x7f8a9b000000,
				End:    0x7f8a9b002000,
				Offset: 0x00001000,
				Perms:  "r-xp",
				Path:   "/usr/lib/libc.so.6",
			},
			wantNil: false,
		},
		{
			name: "find region in heap",
			pc:   0x7f8a9b100100,
			want: &MapRegion{
				Start:  0x7f8a9b100000,
				End:    0x7f8a9b102000,
				Offset: 0x00002000,
				Perms:  "rw-p",
				Path:   "[heap]",
			},
			wantNil: false,
		},
		{
			name:    "not found - before first region",
			pc:      0x1000,
			wantNil: true,
		},
		{
			name:    "not found - between regions",
			pc:      0x55d4b2021001,
			wantNil: true,
		},
		{
			name:    "not found - after last region",
			pc:      0xffffffffffffffff,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maps.FindRegion(tt.pc)
			if tt.wantNil {
				if got != nil {
					t.Errorf("FindRegion() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Errorf("FindRegion() = nil, want %v", tt.want)
				return
			}
			if got.Start != tt.want.Start {
				t.Errorf("FindRegion() Start = %x, want %x", got.Start, tt.want.Start)
			}
			if got.End != tt.want.End {
				t.Errorf("FindRegion() End = %x, want %x", got.End, tt.want.End)
			}
			if got.Path != tt.want.Path {
				t.Errorf("FindRegion() Path = %q, want %q", got.Path, tt.want.Path)
			}
			if got.Perms != tt.want.Perms {
				t.Errorf("FindRegion() Perms = %q, want %q", got.Perms, tt.want.Perms)
			}
		})
	}
}

func TestProcMaps_Refresh(t *testing.T) {
	tests := []struct {
		name       string
		initial    []string
		refreshed  []string
		wantErr    bool
		verifyFunc func(*testing.T, *procMaps)
	}{
		{
			name: "refresh with new mappings",
			initial: []string{
				"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
			},
			refreshed: []string{
				"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
				"7f8a9b000000-7f8a9b002000 r-xp 00001000 08:01 131074 /usr/lib/libc.so.6",
			},
			wantErr: false,
			verifyFunc: func(t *testing.T, m *procMaps) {
				if len(m.regions) != 2 {
					t.Errorf("expected 2 regions after refresh, got %d", len(m.regions))
				}
			},
		},
		{
			name: "refresh removes mappings",
			initial: []string{
				"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
				"7f8a9b000000-7f8a9b002000 r-xp 00001000 08:01 131074 /usr/lib/libc.so.6",
			},
			refreshed: []string{
				"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
			},
			wantErr: false,
			verifyFunc: func(t *testing.T, m *procMaps) {
				if len(m.regions) != 1 {
					t.Errorf("expected 1 region after refresh, got %d", len(m.regions))
				}
			},
		},
		{
			name: "refresh error",
			initial: []string{
				"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
			},
			refreshed: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockReader := &mockMapsReader{lines: tt.initial}
			maps, err := NewProcMaps(1234, mockReader)
			if err != nil {
				t.Fatalf("NewProcMaps() error = %v", err)
			}

			mockReader.lines = tt.refreshed
			if tt.wantErr {
				mockReader.err = errors.New("read error")
			} else {
				mockReader.err = nil
			}

			err = maps.Refresh()
			if (err != nil) != tt.wantErr {
				t.Errorf("Refresh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.verifyFunc != nil {
				tt.verifyFunc(t, maps)
			}
		})
	}
}

func TestProcMaps_ParseMapsWithInvalidLines(t *testing.T) {
	reader := &mockMapsReader{
		lines: []string{
			"55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog",
			"invalid line that cannot be parsed",
			"",
			"7f8a9b000000-7f8a9b002000 r-xp 00001000 08:01 131074 /usr/lib/libc.so.6",
			"not enough fields",
		},
	}

	maps, err := NewProcMaps(1234, reader)
	if err != nil {
		t.Fatalf("NewProcMaps() error = %v", err)
	}

	if len(maps.regions) != 2 {
		t.Errorf("expected 2 valid regions, got %d", len(maps.regions))
	}

	found := false
	for _, r := range maps.regions {
		if r.Path == "/usr/bin/myprog" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find /usr/bin/myprog region")
	}
}

func TestProcMaps_EmptyMaps(t *testing.T) {
	reader := &mockMapsReader{
		lines: []string{},
	}

	maps, err := NewProcMaps(1234, reader)
	if err != nil {
		t.Fatalf("NewProcMaps() error = %v", err)
	}

	if got := maps.FindRegion(0x1000); got != nil {
		t.Errorf("FindRegion() = %v, want nil", got)
	}
}
