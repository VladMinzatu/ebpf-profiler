package symbolizer

import (
	"errors"
	"testing"
	"time"
)

type mockProcMapsProvider struct {
	regions      []MapRegion
	findErr      error
	refreshErr   error
	refreshCalls int
}

func (m *mockProcMapsProvider) FindRegion(pc uint64) *MapRegion {
	if m.findErr != nil {
		return nil
	}
	for i := range m.regions {
		r := &m.regions[i]
		if pc >= r.Start && pc < r.End {
			return r
		}
	}
	return nil
}

func (m *mockProcMapsProvider) Refresh() error {
	m.refreshCalls++
	return m.refreshErr
}

type mockProcMapsProviderWithCustomFind struct {
	mockProcMapsProvider
	findRegionFunc func(pc uint64) *MapRegion
}

func (m *mockProcMapsProviderWithCustomFind) FindRegion(pc uint64) *MapRegion {
	if m.findRegionFunc != nil {
		return m.findRegionFunc(pc)
	}
	return m.mockProcMapsProvider.FindRegion(pc)
}

type mockSymbolResolver struct {
	symbols map[string]map[uint64]*Symbol
	err     error
}

func (m *mockSymbolResolver) ResolvePC(path string, pc uint64, slide uint64) (*Symbol, error) {
	if m.err != nil {
		return nil, m.err
	}
	var symMap map[uint64]*Symbol
	var ok bool
	if symMap, ok = m.symbols[path]; !ok {
		return nil, errors.New("symbol data not found")
	}
	target := pc - slide
	if sym, ok := symMap[target]; ok {
		return sym, nil
	}

	return &Symbol{Name: "unknown", Addr: target}, nil
}

func TestUserSymbolizer_Symbolize(t *testing.T) {
	tests := []struct {
		name           string
		stack          []uint64
		mapsProvider   *mockProcMapsProvider
		symbolResolver *mockSymbolResolver
		wantSymbols    int
		wantErr        bool
		errContains    string
	}{
		{
			name:  "successful symbolization",
			stack: []uint64{0x55d4b2000100, 0x7f8a9b000100},
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x55d4b2000000, End: 0x55d4b2021000, Offset: 0x0, Path: "/usr/bin/myprog"},
					{Start: 0x7f8a9b000000, End: 0x7f8a9b002000, Offset: 0x1000, Path: "/usr/lib/libc.so.6"},
				},
			},
			symbolResolver: &mockSymbolResolver{
				symbols: map[string]map[uint64]*Symbol{
					"/usr/bin/myprog": map[uint64]*Symbol{
						0x100: {Name: "main"},
					},
					"/usr/lib/libc.so.6": map[uint64]*Symbol{
						0x100: {Name: "printf"},
					},
				},
			},
			wantSymbols: 2,
			wantErr:     false,
		},
		{
			name:  "region not found - cache refresh and retry",
			stack: []uint64{0x55d4b2000100, 0xdeadbeef0000},
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x55d4b2000000, End: 0x55d4b2021000, Offset: 0x0, Path: "/usr/bin/myprog"},
				},
			},
			symbolResolver: &mockSymbolResolver{
				symbols: map[string]map[uint64]*Symbol{
					"/usr/bin/myprog": map[uint64]*Symbol{
						0x100: {Name: "main"},
					},
				},
			},
			wantSymbols: 1,
			wantErr:     false,
		},
		{
			name:  "symbol data provider error",
			stack: []uint64{0x55d4b2000100},
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x55d4b2000000, End: 0x55d4b2021000, Offset: 0x0, Path: "/usr/bin/myprog"},
				},
			},
			symbolResolver: &mockSymbolResolver{
				err: errors.New("provider error"),
			},
			wantErr:     true,
			errContains: "failed to resolve symbol",
		},
		{
			name:  "symbol data not found for path",
			stack: []uint64{0x55d4b2000100},
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x55d4b2000000, End: 0x55d4b2021000, Offset: 0x0, Path: "/usr/bin/myprog"},
				},
			},
			symbolResolver: &mockSymbolResolver{
				symbols: map[string]map[uint64]*Symbol{},
			},
			wantErr:     true,
			errContains: "failed to resolve symbol",
		},
		{
			name:  "empty stack",
			stack: []uint64{},
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{},
			},
			symbolResolver: &mockSymbolResolver{
				symbols: map[string]map[uint64]*Symbol{},
			},
			wantSymbols: 0,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewUserSymbolizer(1234, tt.mapsProvider, tt.symbolResolver)

			symbols, err := s.Symbolize(tt.stack)
			if (err != nil) != tt.wantErr {
				t.Errorf("Symbolize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("error message %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if len(symbols) != tt.wantSymbols {
				t.Errorf("Symbolize() returned %d symbols, want %d", len(symbols), tt.wantSymbols)
			}
		})
	}
}

func TestUserSymbolizer_getMapsProvider(t *testing.T) {
	tests := []struct {
		name          string
		mapsProvider  *mockProcMapsProvider
		cachedAt      time.Time
		wantErr       bool
		errContains   string
		checkRefresh  bool
		expectRefresh bool
	}{
		{
			name: "cache hit - within TTL",
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
				},
			},
			cachedAt:      time.Now().Add(-1 * time.Second),
			wantErr:       false,
			checkRefresh:  true,
			expectRefresh: false,
		},
		{
			name: "cache miss - expired TTL",
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
				},
			},
			cachedAt:      time.Now().Add(-10 * time.Second),
			wantErr:       false,
			checkRefresh:  true,
			expectRefresh: true,
		},
		{
			name: "refresh error",
			mapsProvider: &mockProcMapsProvider{
				refreshErr: errors.New("refresh failed"),
			},
			cachedAt:      time.Now().Add(-10 * time.Second),
			wantErr:       true,
			errContains:   "failed to refresh maps",
			checkRefresh:  false,
			expectRefresh: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &UserSymbolizer{
				pid:            1234,
				mapsProvider:   tt.mapsProvider,
				mapsCachedAt:   tt.cachedAt,
				mapsCacheTtl:   5 * time.Second,
				symbolResolver: &mockSymbolResolver{symbols: map[string]map[uint64]*Symbol{}},
			}

			initialCalls := tt.mapsProvider.refreshCalls

			maps, err := s.getMapsProvider()

			if (err != nil) != tt.wantErr {
				t.Errorf("getMapsProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errContains != "" && err != nil && !contains(err.Error(), tt.errContains) {
					t.Errorf("error message %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if maps == nil {
				t.Error("getMapsProvider() returned nil maps")
				return
			}

			if tt.checkRefresh {
				if tt.expectRefresh && tt.mapsProvider.refreshCalls <= initialCalls {
					t.Errorf("expected refresh to be called, initial calls: %d, current calls: %d", initialCalls, tt.mapsProvider.refreshCalls)
				}
				if !tt.expectRefresh && tt.mapsProvider.refreshCalls > initialCalls {
					t.Errorf("expected no refresh, but refresh was called")
				}
			}
		})
	}
}

func TestUserSymbolizer_getMapsProvider_CacheExpiration(t *testing.T) {
	mockMaps := &mockProcMapsProvider{
		regions: []MapRegion{
			{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
		},
	}

	s := &UserSymbolizer{
		pid:            1234,
		mapsProvider:   mockMaps,
		mapsCachedAt:   time.Now().Add(-10 * time.Second), // Expired
		mapsCacheTtl:   5 * time.Second,
		symbolResolver: &mockSymbolResolver{symbols: map[string]map[uint64]*Symbol{}},
	}

	// First call should refresh
	maps, err := s.getMapsProvider()
	if err != nil {
		t.Fatalf("getMapsProvider() error = %v", err)
	}
	if maps == nil {
		t.Fatal("getMapsProvider() returned nil maps")
	}

	// Verify refresh was called
	if mockMaps.refreshCalls == 0 {
		t.Error("expected refresh to be called on expired cache")
	}

	// Reset refresh counter
	mockMaps.refreshCalls = 0

	// Update cache time to be fresh
	s.mapsMu.Lock()
	s.mapsCachedAt = time.Now()
	s.mapsMu.Unlock()

	// Second call should use cache (no refresh)
	maps2, err := s.getMapsProvider()
	if err != nil {
		t.Fatalf("getMapsProvider() error = %v", err)
	}
	if maps2 == nil {
		t.Fatal("getMapsProvider() returned nil maps")
	}

	// Verify refresh was NOT called
	if mockMaps.refreshCalls > 0 {
		t.Error("expected no refresh on fresh cache, but refresh was called")
	}
}

func TestUserSymbolizer_refreshMapsProvider(t *testing.T) {
	mockMaps := &mockProcMapsProvider{
		regions: []MapRegion{
			{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
		},
	}

	s := &UserSymbolizer{
		pid:            1234,
		mapsProvider:   mockMaps,
		mapsCachedAt:   time.Unix(0, 0),
		mapsCacheTtl:   5 * time.Second,
		symbolResolver: &mockSymbolResolver{symbols: map[string]map[uint64]*Symbol{}},
	}

	// Verify initial cache time
	if !s.mapsCachedAt.Equal(time.Unix(0, 0)) {
		t.Errorf("expected initial cachedAt to be Unix epoch, got %v", s.mapsCachedAt)
	}

	// Refresh
	err := s.refreshMapsProvider()
	if err != nil {
		t.Fatalf("refreshMapsProvider() error = %v", err)
	}

	// Verify refresh was called
	if mockMaps.refreshCalls == 0 {
		t.Error("expected refresh to be called")
	}

	// Verify cache time was updated (should be recent, within last second)
	if time.Since(s.mapsCachedAt) > time.Second {
		t.Error("expected mapsCachedAt to be updated to recent time")
	}

	// Test refresh error
	mockMaps.refreshErr = errors.New("refresh failed")
	err = s.refreshMapsProvider()
	if err == nil {
		t.Error("expected error from refreshMapsProvider()")
	}
	if err != nil && !contains(err.Error(), "failed to refresh maps") {
		t.Errorf("error message %q does not contain 'failed to refresh maps'", err.Error())
	}
}

func TestUserSymbolizer_Symbolize_WithCacheRefresh(t *testing.T) {
	// First call returns nil for region, refresh happens, then second call succeeds
	calls := 0
	mockMaps := &mockProcMapsProviderWithCustomFind{
		mockProcMapsProvider: mockProcMapsProvider{
			regions: []MapRegion{},
		},
	}
	mockMaps.findRegionFunc = func(pc uint64) *MapRegion {
		calls++
		if calls == 1 {
			return nil // First call fails
		}
		// After refresh, return valid region
		mockMaps.mockProcMapsProvider.regions = []MapRegion{
			{Start: 0x55d4b2000000, End: 0x55d4b2021000, Offset: 0x0, Path: "/usr/bin/myprog"},
		}
		return &mockMaps.regions[0]
	}

	symbolResolver := &mockSymbolResolver{
		symbols: map[string]map[uint64]*Symbol{
			"/usr/bin/myprog": map[uint64]*Symbol{
				0x100: {Name: "main"},
			},
		},
	}

	s := NewUserSymbolizer(1234, mockMaps, symbolResolver)

	// This should trigger cache refresh and retry
	symbols, err := s.Symbolize([]uint64{0x55d4b2000100})
	if err != nil {
		t.Fatalf("Symbolize() error = %v", err)
	}

	// Should eventually get a symbol after refresh
	if len(symbols) == 0 {
		t.Error("expected at least one symbol after cache refresh")
	}

	// Verify refresh was called
	if mockMaps.refreshCalls == 0 {
		t.Error("expected refresh to be called when region not found")
	}
}

func TestNewUserSymbolizer(t *testing.T) {
	mapsProvider := &mockProcMapsProvider{
		regions: []MapRegion{
			{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
		},
	}
	symbolResolver := &mockSymbolResolver{
		symbols: map[string]map[uint64]*Symbol{},
	}
	s := NewUserSymbolizer(1234, mapsProvider, symbolResolver)

	if s == nil {
		t.Fatal("NewUserSymbolizer() returned nil")
	}
	if s.pid != 1234 {
		t.Errorf("NewUserSymbolizer() pid = %d, want 1234", s.pid)
	}
	if s.mapsCacheTtl != 5*time.Second {
		t.Errorf("NewUserSymbolizer() mapsCacheTtl = %v, want 5s", s.mapsCacheTtl)
	}
	if s.mapsProvider != mapsProvider {
		t.Error("NewUserSymbolizer() did not set mapsProvider correctly")
	}
	if s.symbolResolver != symbolResolver {
		t.Error("NewUserSymbolizer() did not set symbolDataProvider correctly")
	}
	if !s.mapsCachedAt.Equal(time.Unix(0, 0)) {
		t.Errorf("NewUserSymbolizer() mapsCachedAt = %v, want Unix(0,0)", s.mapsCachedAt)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				findSubstring(s, substr))))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
