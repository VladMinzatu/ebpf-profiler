package symbolizer

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type UserSymbolizer struct {
	pid int

	symbolDataProvider SymbolDataProvider
	mapsProvider       ProcMapsProvider

	mapsCachedAt time.Time
	mapsCacheTtl time.Duration
	mapsMu       sync.RWMutex
}

func NewUserSymbolizer(pid int, procMapsProvider ProcMapsProvider, symbolDataProvider SymbolDataProvider) *UserSymbolizer {
	return &UserSymbolizer{
		pid:                pid,
		symbolDataProvider: symbolDataProvider,
		mapsProvider:       procMapsProvider,

		mapsCachedAt: time.Unix(0, 0),
		mapsCacheTtl: 5 * time.Second,
	}
}

func (s *UserSymbolizer) Symbolize(stack []uint64) ([]Symbol, error) {
	maps, err := s.getMapsProvider()
	if err != nil {
		return nil, fmt.Errorf("symbolization failed due to failure to read proc maps: %v", err)
	}
	var symbols []Symbol
	for _, pc := range stack {
		r := maps.FindRegion(pc)
		if r == nil {
			slog.Debug("Did not find map region for PC, invalidating cache and retrying", "pc", pc)
			err = s.refreshMapsProvider()
			if err != nil {
				return nil, fmt.Errorf("symbolization failed due to failure to read proc maps: %v", err)
			}
			maps = s.mapsProvider
			r = maps.FindRegion(pc)
			if r == nil {
				slog.Warn("Did not find map region for PC after cache refresh", "pc", pc)
				continue
			}
		}

		symbolData, err := s.symbolDataProvider.Get(r.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve symbol for pc=%d: %v", pc, err)
		}
		symbol, err := symbolData.ResolvePC(pc, r.Offset)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve symbol for pc=%d: %v", pc, err)
		}
		symbols = append(symbols, *symbol)
	}
	return symbols, nil
}

func (s *UserSymbolizer) getMapsProvider() (ProcMapsProvider, error) {
	s.mapsMu.RLock()
	if time.Since(s.mapsCachedAt) < s.mapsCacheTtl {
		mapsProvider := s.mapsProvider
		s.mapsMu.RUnlock()
		return mapsProvider, nil
	}
	s.mapsMu.RUnlock()

	err := s.refreshMapsProvider()
	if err != nil {
		return nil, err
	}
	return s.mapsProvider, nil
}

func (s *UserSymbolizer) refreshMapsProvider() error {
	s.mapsMu.Lock()
	defer s.mapsMu.Unlock()
	err := s.mapsProvider.Refresh()
	if err != nil {
		return fmt.Errorf("failed to refresh maps: %v", err)
	}

	s.mapsCachedAt = time.Now()
	return nil
}
