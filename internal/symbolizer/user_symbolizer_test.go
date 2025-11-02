package symbolizer

import (
	"errors"
	"testing"
	"time"
	"unsafe"
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

type mockSymbolData struct {
	symbols map[uint64]*Symbol
	err     error
}

func (m *mockSymbolData) ResolvePC(pc uint64, slide uint64) (*Symbol, error) {
	if m.err != nil {
		return nil, m.err
	}
	target := pc - slide
	if sym, ok := m.symbols[target]; ok {
		return sym, nil
	}

	if len(m.symbols) > 0 {
		for _, sym := range m.symbols {
			return &Symbol{Name: sym.Name, PC: target}, nil
		}
	}
	return &Symbol{Name: "unknown", PC: target}, nil
}

type mockSymbolDataProvider struct {
	data map[string]*mockSymbolData
	err  error
}

func (m *mockSymbolDataProvider) Get(path string) (*SymbolData, error) {
	if m.err != nil {
		return nil, m.err
	}
	if mockData, ok := m.data[path]; ok {
		wrapper := &testSymbolDataWrapper{mock: mockData}
		return (*SymbolData)(unsafe.Pointer(wrapper)), nil
	}
	return nil, errors.New("symbol data not found")
}

type testSymbolDataWrapper struct {
	SymbolData
	mock *mockSymbolData
}

func (t *testSymbolDataWrapper) ResolvePC(pc uint64, slide uint64) (*Symbol, error) {
	return t.mock.ResolvePC(pc, slide)
}

func TestUserSymbolizer_Symbolize(t *testing.T) {
	tests := []struct {
		name           string
		stack          []uint64
		mapsProvider   *mockProcMapsProvider
		symbolProvider *mockSymbolDataProvider
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
			symbolProvider: &mockSymbolDataProvider{
				data: map[string]*mockSymbolData{
					"/usr/bin/myprog": {
						symbols: map[uint64]*Symbol{
							0x100: {Name: "main", PC: 0},
						},
					},
					"/usr/lib/libc.so.6": {
						symbols: map[uint64]*Symbol{
							0x100: {Name: "printf", PC: 0},
						},
					},
				},
			},
			wantSymbols: 2,
			wantErr:     false,
		},
		{
			name:  "region not found - cache invalidation and retry",
			stack: []uint64{0x55d4b2000100, 0xdeadbeef0000},
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x55d4b2000000, End: 0x55d4b2021000, Offset: 0x0, Path: "/usr/bin/myprog"},
				},
			},
			symbolProvider: &mockSymbolDataProvider{
				data: map[string]*mockSymbolData{
					"/usr/bin/myprog": {
						symbols: map[uint64]*Symbol{
							0x100: {Name: "main", PC: 0},
						},
					},
				},
			},
			wantSymbols: 1, // Only first PC gets symbolized
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
			symbolProvider: &mockSymbolDataProvider{
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
			symbolProvider: &mockSymbolDataProvider{
				data: map[string]*mockSymbolData{},
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
			symbolProvider: &mockSymbolDataProvider{
				data: map[string]*mockSymbolData{},
			},
			wantSymbols: 0,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &UserSymbolizer{
				pid:                1234,
				symbolDataProvider: tt.symbolProvider,
				mapsCache: &mapsCache{
					maps:     tt.mapsProvider,
					cachedAt: time.Now(),
					ttl:      5 * time.Second,
				},
				mapsTTL: 5 * time.Second,
			}

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

func TestUserSymbolizer_getMaps(t *testing.T) {
	tests := []struct {
		name          string
		cacheState    *mapsCache
		mapsProvider  *mockProcMapsProvider
		wantErr       bool
		errContains   string
		checkRefresh  bool
		expectRefresh bool
	}{
		{
			name: "cache hit - within TTL",
			cacheState: &mapsCache{
				maps: &mockProcMapsProvider{
					regions: []MapRegion{
						{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
					},
				},
				cachedAt: time.Now().Add(-1 * time.Second),
				ttl:      5 * time.Second,
			},
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
				},
			},
			wantErr:       false,
			checkRefresh:  true,
			expectRefresh: false,
		},
		{
			name: "cache miss - expired TTL",
			cacheState: &mapsCache{
				maps: &mockProcMapsProvider{
					regions: []MapRegion{
						{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
					},
				},
				cachedAt: time.Now().Add(-10 * time.Second),
				ttl:      5 * time.Second,
			},
			mapsProvider: &mockProcMapsProvider{
				regions: []MapRegion{
					{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
				},
			},
			wantErr:       false,
			checkRefresh:  true,
			expectRefresh: true,
		},
		{
			name: "refresh error",
			cacheState: &mapsCache{
				maps: &mockProcMapsProvider{
					refreshErr: errors.New("refresh failed"),
				},
				cachedAt: time.Now().Add(-10 * time.Second),
				ttl:      5 * time.Second,
			},
			mapsProvider: &mockProcMapsProvider{
				refreshErr: errors.New("refresh failed"),
			},
			wantErr:     true,
			errContains: "failed to refresh maps",
		},
		{
			name:         "no cache - nil mapsCache",
			cacheState:   nil,
			mapsProvider: &mockProcMapsProvider{},
			wantErr:      true,
			errContains:  "nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &UserSymbolizer{
				pid:                1234,
				mapsCache:          tt.cacheState,
				mapsTTL:            5 * time.Second,
				symbolDataProvider: &mockSymbolDataProvider{data: map[string]*mockSymbolData{}},
			}

			if tt.checkRefresh && tt.cacheState != nil {
				mockProvider := tt.cacheState.maps.(*mockProcMapsProvider)
				initialCalls := mockProvider.refreshCalls

				maps, err := s.getMaps()

				if (err != nil) != tt.wantErr {
					t.Errorf("getMaps() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				if tt.wantErr {
					if tt.errContains != "" && err != nil && !contains(err.Error(), tt.errContains) {
						t.Errorf("error message %q does not contain %q", err.Error(), tt.errContains)
					}
					return
				}

				if maps == nil {
					t.Error("getMaps() returned nil maps")
					return
				}

				if tt.checkRefresh {
					if tt.expectRefresh && mockProvider.refreshCalls <= initialCalls {
						t.Errorf("expected refresh to be called, initial calls: %d, current calls: %d", initialCalls, mockProvider.refreshCalls)
					}
					if !tt.expectRefresh && mockProvider.refreshCalls > initialCalls {
						t.Errorf("expected no refresh, but refresh was called")
					}
				}
			} else {
				_, err := s.getMaps()
				if (err != nil) != tt.wantErr {
					t.Errorf("getMaps() error = %v, wantErr %v", err, tt.wantErr)
				}
				if tt.wantErr && tt.errContains != "" && err != nil && !contains(err.Error(), tt.errContains) {
					t.Errorf("error message %q does not contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestUserSymbolizer_getMaps_CacheExpiration(t *testing.T) {
	mockMaps := &mockProcMapsProvider{
		regions: []MapRegion{
			{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
		},
	}

	s := &UserSymbolizer{
		pid: 1234,
		mapsCache: &mapsCache{
			maps:     mockMaps,
			cachedAt: time.Now().Add(-10 * time.Second), // Expired
			ttl:      5 * time.Second,
		},
		mapsTTL:            5 * time.Second,
		symbolDataProvider: &mockSymbolDataProvider{data: map[string]*mockSymbolData{}},
	}

	// First call should refresh
	maps, err := s.getMaps()
	if err != nil {
		t.Fatalf("getMaps() error = %v", err)
	}
	if maps == nil {
		t.Fatal("getMaps() returned nil maps")
	}

	// Verify refresh was called
	if mockMaps.refreshCalls == 0 {
		t.Error("expected refresh to be called on expired cache")
	}

	// Reset refresh counter
	mockMaps.refreshCalls = 0

	// Update cache time to be fresh
	s.mapsMu.Lock()
	s.mapsCache.cachedAt = time.Now()
	s.mapsMu.Unlock()

	// Second call should use cache (no refresh)
	maps2, err := s.getMaps()
	if err != nil {
		t.Fatalf("getMaps() error = %v", err)
	}
	if maps2 == nil {
		t.Fatal("getMaps() returned nil maps")
	}

	// Verify refresh was NOT called
	if mockMaps.refreshCalls > 0 {
		t.Error("expected no refresh on fresh cache, but refresh was called")
	}
}

func TestUserSymbolizer_invalidateMaps(t *testing.T) {
	mockMaps := &mockProcMapsProvider{
		regions: []MapRegion{
			{Start: 0x1000, End: 0x2000, Path: "/bin/test"},
		},
	}

	s := &UserSymbolizer{
		pid: 1234,
		mapsCache: &mapsCache{
			maps:     mockMaps,
			cachedAt: time.Now(),
			ttl:      5 * time.Second,
		},
		mapsTTL:            5 * time.Second,
		symbolDataProvider: &mockSymbolDataProvider{data: map[string]*mockSymbolData{}},
	}

	// Verify cache exists
	if s.mapsCache == nil {
		t.Fatal("expected mapsCache to be initialized")
	}

	// Invalidate
	s.invalidateMaps()

	// Verify cache is cleared
	if s.mapsCache != nil {
		t.Error("expected mapsCache to be nil after invalidation")
	}
}

func TestUserSymbolizer_Symbolize_WithCacheInvalidation(t *testing.T) {
	// First call returns nil for region, second call succeeds
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

	s := &UserSymbolizer{
		pid: 1234,
		mapsCache: &mapsCache{
			maps:     mockMaps,
			cachedAt: time.Now(),
			ttl:      5 * time.Second,
		},
		mapsTTL: 5 * time.Second,
		symbolDataProvider: &mockSymbolDataProvider{
			data: map[string]*mockSymbolData{
				"/usr/bin/myprog": {
					symbols: map[uint64]*Symbol{
						0x100: {Name: "main", PC: 0},
					},
				},
			},
		},
	}

	// This should trigger cache invalidation and retry
	symbols, err := s.Symbolize([]uint64{0x55d4b2000100})
	if err != nil {
		t.Fatalf("Symbolize() error = %v", err)
	}

	// Should eventually get a symbol after refresh
	if len(symbols) == 0 {
		t.Error("expected at least one symbol after cache refresh")
	}

	// Verify cache was invalidated (mapsCache should be nil initially after invalidation)
	// Then recreated in getMaps
}

func TestNewUserSymbolizer(t *testing.T) {
	cache := NewSymbolDataCache(1234)
	s := NewUserSymbolizer(cache, 1234)

	if s == nil {
		t.Fatal("NewUserSymbolizer() returned nil")
	}
	if s.pid != 1234 {
		t.Errorf("NewUserSymbolizer() pid = %d, want 1234", s.pid)
	}
	if s.mapsTTL != 5*time.Second {
		t.Errorf("NewUserSymbolizer() mapsTTL = %v, want 5s", s.mapsTTL)
	}
}

func TestNewUserSymbolizerWithReader(t *testing.T) {
	provider := &mockSymbolDataProvider{
		data: map[string]*mockSymbolData{},
	}
	s := NewUserSymbolizer(provider, 1234)

	if s == nil {
		t.Fatal("NewUserSymbolizer() returned nil")
	}
	if s.pid != 1234 {
		t.Errorf("NewUserSymbolizer() pid = %d, want 1234", s.pid)
	}
	if s.symbolDataProvider != provider {
		t.Error("NewUserSymbolizer() did not set symbolDataProvider correctly")
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
