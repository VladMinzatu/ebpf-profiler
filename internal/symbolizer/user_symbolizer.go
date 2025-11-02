package symbolizer

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type ProcMapsProvider interface {
	FindRegion(pc uint64) *MapRegion
	Refresh() error
}

type mapsCache struct {
	maps     ProcMapsProvider
	cachedAt time.Time
	ttl      time.Duration
}

type UserSymbolizer struct {
	pid int

	symbolDataCache *SymbolDataCache
	mapsCache       *mapsCache
	mapsMu          sync.RWMutex
	mapsTTL         time.Duration
}

func NewUserSymbolizer(symbolDataCache *SymbolDataCache, pid int) *UserSymbolizer {
	return NewUserSymbolizerWithReader(symbolDataCache, pid)
}

func NewUserSymbolizerWithReader(symbolDataCache *SymbolDataCache, pid int) *UserSymbolizer {
	return &UserSymbolizer{
		symbolDataCache: symbolDataCache,
		pid:             pid,
		mapsTTL:         5 * time.Second,
	}
}

func (s *UserSymbolizer) Symbolize(stack []uint64) ([]Symbol, error) {
	maps, err := s.getMaps()
	if err != nil {
		return nil, fmt.Errorf("symbolization failed due to failure to read proc maps: %v", err)
	}
	var symbols []Symbol
	for _, pc := range stack {
		r := maps.FindRegion(pc)
		if r == nil {
			slog.Debug("Did not find map region for PC, invalidating cache and retrying", "pc", pc)
			s.invalidateMaps()
			maps, err = s.getMaps()
			if err != nil {
				return nil, fmt.Errorf("symbolization failed due to failure to read proc maps: %v", err)
			}
			r = maps.FindRegion(pc)
			if r == nil {
				slog.Warn("Did not find map region for PC after cache refresh", "pc", pc)
				continue
			}
		}

		symbolData, err := s.symbolDataCache.Get(r.Path)
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

func (s *UserSymbolizer) getMaps() (ProcMapsProvider, error) {
	s.mapsMu.RLock()
	if s.mapsCache != nil && time.Since(s.mapsCache.cachedAt) < s.mapsCache.ttl {
		maps := s.mapsCache.maps
		s.mapsMu.RUnlock()
		return maps, nil
	}
	s.mapsMu.RUnlock()

	s.mapsMu.Lock()
	defer s.mapsMu.Unlock()

	if s.mapsCache != nil && time.Since(s.mapsCache.cachedAt) < s.mapsCache.ttl {
		return s.mapsCache.maps, nil
	}
	err := s.mapsCache.maps.Refresh()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh maps: %v", err)
	}

	s.mapsCache = &mapsCache{
		maps:     s.mapsCache.maps,
		cachedAt: time.Now(),
		ttl:      s.mapsTTL,
	}
	return s.mapsCache.maps, nil
}

func (s *UserSymbolizer) invalidateMaps() {
	s.mapsMu.Lock()
	defer s.mapsMu.Unlock()
	s.mapsCache = nil
}
