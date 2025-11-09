package symbolizer

import (
	"errors"
	"testing"
)

type callRecordingLoader struct {
	lines []string
	err   error
	calls int
}

func (m *callRecordingLoader) ReadLines() ([]string, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.lines, nil
}

func TestKernelSymbolizer_SuccessfulInitAndSymbolize(t *testing.T) {
	// unordered on purpose
	lines := []string{
		"ffffffff81000000 T start_kernel",
		"ffffffff81001000 T do_one",
		"ffffffff81002000 T do_two",
	}

	loader := &callRecordingLoader{lines: lines}
	s := NewKernelSymbolizer(loader)

	stack := []uint64{
		0xffffffff81000000,
		0xffffffff81001020,
		0xffffffff81002005,
	}

	syms, err := s.Symbolize(stack)
	if err != nil {
		t.Fatalf("Symbolize returned unexpected error: %v", err)
	}

	if len(syms) != 3 {
		t.Fatalf("expected 3 symbols, got %d", len(syms))
	}

	tests := []struct {
		i          int
		wantName   string
		wantAddr   uint64
		wantOffset uint64
	}{
		{0, "start_kernel", 0xffffffff81000000, 0},
		{1, "do_one", 0xffffffff81001000, 0x20},
		{2, "do_two", 0xffffffff81002000, 0x5},
	}

	for _, tt := range tests {
		got := syms[tt.i]
		if got.Name != tt.wantName {
			t.Errorf("symbol %d: want name %q got %q", tt.i, tt.wantName, got.Name)
		}
		if got.Addr != tt.wantAddr {
			t.Errorf("symbol %d: want address 0x%x got 0x%x", tt.i, tt.wantAddr, got.Addr)
		}
		if got.Offset != tt.wantOffset {
			t.Errorf("symbol %d: want offset 0x%x got 0x%x", tt.i, tt.wantOffset, got.Offset)
		}
	}

	// mind the lazy init
	if loader.calls != 1 {
		t.Fatalf("expected loader.ReadLines called once, got %d", loader.calls)
	}

	// resolver should be cached now
	_, err = s.Symbolize([]uint64{0xffffffff81001000})
	if err != nil {
		t.Fatalf("second Symbolize returned unexpected error: %v", err)
	}
	if loader.calls != 1 {
		t.Fatalf("expected loader.ReadLines to still have been called once after second Symbolize, got %d", loader.calls)
	}
}

func TestKernelSymbolizer_InitErrorIsCachedAndReturned(t *testing.T) {
	wantErr := errors.New("read failed")
	loader := &callRecordingLoader{err: wantErr}
	s := NewKernelSymbolizer(loader)

	_, err := s.Symbolize([]uint64{0x1000})
	if err == nil {
		t.Fatalf("expected error when kallsyms loader fails, got nil")
	}
	if err.Error() != "no resolver for kernel symbolization could be loaded" {
		t.Fatalf("unexpected error message: %v", err)
	}

	if loader.calls != 1 {
		t.Fatalf("expected loader.ReadLines called once, got %d", loader.calls)
	}

	// error is cached, so retry not expected
	_, err2 := s.Symbolize([]uint64{0x2000})
	if err2 == nil {
		t.Fatalf("expected error on second call when init previously failed, got nil")
	}
	if loader.calls != 1 {
		t.Fatalf("expected loader.ReadLines not to be called again after cached init error; calls=%d", loader.calls)
	}
}

func TestKernelSymbolizer_SkipsUnresolvableFrames(t *testing.T) {
	lines := []string{
		"ffffffff81001000 T do_one",
	}
	loader := &callRecordingLoader{lines: lines}
	s := NewKernelSymbolizer(loader)

	stack := []uint64{
		0xffffffff80ffff00,
		0xffffffff81001005,
		0xffffffffffffffff,
	}

	syms, err := s.Symbolize(stack)
	if err != nil {
		t.Fatalf("Symbolize returned unexpected error: %v", err)
	}

	if len(syms) != 2 {
		t.Fatalf("expected 2 symbols after skipping unresolvable frame, got %d", len(syms))
	}

	if syms[0].Name != "do_one" || syms[0].Offset != 5 {
		t.Fatalf("unexpected first symbol: %+v", syms[0])
	}

	expectedOffset := uint64(0xffffffffffffffff) - 0xffffffff81001000
	if syms[1].Name != "do_one" || syms[1].Offset != expectedOffset {
		t.Fatalf("unexpected second symbol: want name do_one, address 0x%x, offset 0x%x, got %+v", uint64(0xffffffffffffffff), expectedOffset, syms[1])
	}

	if loader.calls != 1 {
		t.Fatalf("expected loader.ReadLines called once, got %d", loader.calls)
	}
}
