package symbolizer

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type mockLoader struct {
	lines []string
	err   error
}

func (m *mockLoader) ReadLines() ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.lines, nil
}

func TestInitKallsymsResolver_and_Resolve(t *testing.T) {
	t.Run("parses_lines_sorts_and_resolves_offsets", func(t *testing.T) {
		// note: input is unordered
		lines := []string{
			// valid entries (modules or extra fields allowed and ignored)
			"ffffffff81001000 T do_one",
			"ffffffff81000000 T start_kernel [kernel]",
			"ffffffff81002000 T do_two    extra_field",
			// malformed entries (should be skipped)
			"badline",
			"zzzzzzzzzzzz T invalid_addr",
			"ffffffff81003000",
			"\tffffffff81003000\tT\tlast_func",
		}

		resolver, err := InitKallsymsResolver(&mockLoader{lines: lines})
		if err != nil {
			t.Fatalf("InitKallsymsResolver returned error: %v", err)
		}

		tests := []struct {
			pc           uint64
			wantName     string
			wantOffset   uint64
			expectErr    bool
			errSubstring string
		}{
			{pc: 0xffffffff81000000, wantName: "start_kernel", wantOffset: 0, expectErr: false},
			{pc: 0xffffffff81001010, wantName: "do_one", wantOffset: 0x10, expectErr: false},
			{pc: 0xffffffff81002005, wantName: "do_two", wantOffset: 0x5, expectErr: false},
			{pc: 0xffffffff81003000, wantName: "last_func", wantOffset: 0, expectErr: false},
			{pc: 0xffffffff80fffeff, expectErr: true, errSubstring: "no kernel symbol"},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(fmt.Sprintf("pc=0x%x", tt.pc), func(t *testing.T) {
				sym, err := resolver.Resolve(tt.pc)
				if tt.expectErr {
					if err == nil {
						t.Fatalf("expected error for pc=0x%x but got symbol %+v", tt.pc, sym)
					}
					if tt.errSubstring != "" && !strings.Contains(err.Error(), tt.errSubstring) {
						t.Fatalf("expected error to contain %q, got %v", tt.errSubstring, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("Resolve returned error: %v", err)
				}
				if sym == nil {
					t.Fatalf("Resolve returned nil symbol and nil error")
				}
				if sym.Name != tt.wantName {
					t.Fatalf("unexpected symbol name: want %q got %q", tt.wantName, sym.Name)
				}
				if sym.PC != tt.wantOffset {
					t.Fatalf("unexpected offset: want 0x%x got 0x%x", tt.wantOffset, sym.PC)
				}
			})
		}
	})

	t.Run("init_returns_error_when_loader_errors", func(t *testing.T) {
		wantErr := errors.New("read failed")
		_, err := InitKallsymsResolver(&mockLoader{err: wantErr})
		if err == nil {
			t.Fatalf("expected error but got nil")
		}
		if !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("expected underlying error message to be present; got: %v", err)
		}
	})

	t.Run("resolve_on_empty_table_returns_error", func(t *testing.T) {
		resolver, err := InitKallsymsResolver(&mockLoader{lines: []string{}})
		if err != nil {
			t.Fatalf("InitKallsymsResolver returned unexpected error: %v", err)
		}
		if resolver == nil {
			t.Fatalf("expected resolver (possibly with empty table), got nil")
		}
		_, err = resolver.Resolve(0x1000)
		if err == nil {
			t.Fatalf("expected error when resolving against empty kallsyms table")
		}
		if !strings.Contains(err.Error(), "empty kallsyms table") {
			t.Fatalf("expected 'empty kallsyms table' error, got: %v", err)
		}
	})

	t.Run("lines_with_extra_whitespace_and_modules_are_handled", func(t *testing.T) {
		lines := []string{
			"  ffffffff81010000    T   spaced_name    [mod]  ",
			"ffffffff81020000\tT\ttab_name",
		}
		resolver, err := InitKallsymsResolver(&mockLoader{lines: lines})
		if err != nil {
			t.Fatalf("InitKallsymsResolver returned error: %v", err)
		}

		s, err := resolver.Resolve(0xffffffff81010005)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.Name != "spaced_name" {
			t.Fatalf("expected spaced_name, got %q", s.Name)
		}
		if s.PC != 5 {
			t.Fatalf("expected offset 5, got 0x%x", s.PC)
		}

		s2, err := resolver.Resolve(0xffffffff81020010)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s2.Name != "tab_name" {
			t.Fatalf("expected tab_name, got %q", s2.Name)
		}
	})
}
