package symbolizer

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type mockInternalResolver struct {
	mu        sync.Mutex
	calls     int
	lastPC    uint64
	lastSlide uint64
	retSymbol *Symbol
	retErr    error
}

func (m *mockInternalResolver) ResolvePC(pc uint64, slide uint64) (*Symbol, error) {
	m.mu.Lock()
	m.calls++
	m.lastPC = pc
	m.lastSlide = slide
	retSym := m.retSymbol
	retErr := m.retErr
	m.mu.Unlock()
	return retSym, retErr
}

type mockSymbolLoader struct {
	mu        sync.Mutex
	calls     int
	resolvers map[string]internalSymbolResolver
	err       error
	delay     time.Duration
}

func (m *mockSymbolLoader) LoadFrom(path string) (internalSymbolResolver, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.mu.Lock()
	m.calls++
	res := m.resolvers[path]
	err := m.err
	m.mu.Unlock()
	if res == nil && err == nil {
		return nil, errors.New("no resolver for path")
	}
	return res, err
}

func (m *mockSymbolLoader) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// Tests for CachingSymbolResolver
func TestCachingSymbolResolver_CachesResolver(t *testing.T) {
	loader := &mockSymbolLoader{
		resolvers: map[string]internalSymbolResolver{},
	}

	r := &mockInternalResolver{retSymbol: &Symbol{Name: "foo", Offset: 0x5}}
	loader.resolvers["/bin/test"] = r

	c := NewCachingSymbolResolver(123)
	c.symbolLoader = loader

	sym, err := c.ResolvePC("/bin/test", 0x1010, 0)
	if err != nil {
		t.Fatalf("unexpected error on first ResolvePC: %v", err)
	}
	if sym == nil || sym.Name != "foo" {
		t.Fatalf("unexpected symbol from first ResolvePC: %+v", sym)
	}

	if loader.Calls() != 1 {
		t.Fatalf("loader called %d times after first resolve; want 1", loader.Calls())
	}

	_, err = c.ResolvePC("/bin/test", 0x1020, 0)
	if err != nil {
		t.Fatalf("unexpected error on second ResolvePC: %v", err)
	}
	if loader.Calls() != 1 {
		t.Fatalf("loader called %d times after second resolve; want 1 (cached)", loader.Calls())
	}
}

// TODO: maybe more sensible to cache errors?
func TestCachingSymbolResolver_LoaderErrorNotCached(t *testing.T) {
	loader := &mockSymbolLoader{
		resolvers: nil,
		err:       errors.New("open failed"),
	}

	c := NewCachingSymbolResolver(1)
	c.symbolLoader = loader

	_, err := c.ResolvePC("/bad", 0x0, 0)
	if err == nil {
		t.Fatalf("expected error from loader")
	}

	_, err = c.ResolvePC("/bad", 0x0, 0)
	if err == nil {
		t.Fatalf("expected error on second call as well")
	}

	if loader.Calls() < 2 {
		t.Fatalf("expected loader to be called at least twice when it errors; calls=%d", loader.Calls())
	}
}

func TestCachingSymbolResolver_DifferentPathsIndependent(t *testing.T) {
	loader := &mockSymbolLoader{resolvers: map[string]internalSymbolResolver{}}
	resA := &mockInternalResolver{retSymbol: &Symbol{Name: "A", Addr: 0x2000, Offset: 1}}
	resB := &mockInternalResolver{retSymbol: &Symbol{Name: "B", Addr: 0x3000, Offset: 2}}
	loader.resolvers["/bin/A"] = resA
	loader.resolvers["/bin/B"] = resB

	c := NewCachingSymbolResolver(1)
	c.symbolLoader = loader

	sa, err := c.ResolvePC("/bin/A", 0x2000, 0)
	if err != nil {
		t.Fatalf("unexpected error resolving A: %v", err)
	}
	if sa.Name != "A" {
		t.Fatalf("expected A, got %v", sa.Name)
	}

	sb, err := c.ResolvePC("/bin/B", 0x3000, 0)
	if err != nil {
		t.Fatalf("unexpected error resolving B: %v", err)
	}
	if sb.Name != "B" {
		t.Fatalf("expected B, got %v", sb.Name)
	}

	if loader.Calls() != 2 {
		t.Fatalf("expected loader called 2 times, got %d", loader.Calls())
	}

	_, _ = c.ResolvePC("/bin/A", 0x2001, 0)
	_, _ = c.ResolvePC("/bin/B", 0x3001, 0)
	if loader.Calls() != 2 {
		t.Fatalf("expected loader still called 2 times after cached resolves, got %d", loader.Calls())
	}
}

func TestCachingSymbolResolver_ResolverReceivesPCAndSlide(t *testing.T) {
	loader := &mockSymbolLoader{
		resolvers: map[string]internalSymbolResolver{},
	}
	mockRes := &mockInternalResolver{retSymbol: &Symbol{Name: "Z"}}
	loader.resolvers["/bin/z"] = mockRes

	c := NewCachingSymbolResolver(1)
	c.symbolLoader = loader

	pc := uint64(0xdeadbeef)
	slide := uint64(0x1000)
	_, err := c.ResolvePC("/bin/z", pc, slide)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockRes.mu.Lock()
	gotPC := mockRes.lastPC
	gotSlide := mockRes.lastSlide
	mockRes.mu.Unlock()

	if gotPC != pc {
		t.Fatalf("resolver received pc %x; want %x", gotPC, pc)
	}
	if gotSlide != slide {
		t.Fatalf("resolver received slide %x; want %x", gotSlide, slide)
	}
}

func TestCachingSymbolResolver_ConcurrentLoadOnlyOnce(t *testing.T) {
	loader := &mockSymbolLoader{
		resolvers: map[string]internalSymbolResolver{},
		delay:     50 * time.Millisecond,
	}

	r := &mockInternalResolver{retSymbol: &Symbol{Name: "concurrent"}}
	loader.resolvers["/concurrent"] = r

	c := NewCachingSymbolResolver(1)
	c.symbolLoader = loader

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, _ = c.ResolvePC("/concurrent", 0x1000, 0)
		}()
	}

	close(start)
	wg.Wait()

	if loader.Calls() != 1 {
		t.Fatalf("expected loader called once, got %d", loader.Calls())
	}
}
