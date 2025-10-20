package profiler

import (
	"errors"
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	missingSentinel = 0xFFFFFFFF // as used in the C code
	maxStackFrames  = 127        // max frames in the stacks map (must match what the C code expects)
)

type ebpfProfiler struct {
	objs    profileObjects
	perfFDs []int
	mu      sync.Mutex
	started bool
}

func NewEbpfProfiler() (*ebpfProfiler, error) {
	var e ebpfProfiler
	if err := loadProfileObjects(&e.objs, nil); err != nil {
		return nil, fmt.Errorf("loading bpf objects: %w", err)
	}
	return &e, nil
}

func (e *ebpfProfiler) Start(targetPID int, samplingPeriodNs uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		return errors.New("profiler already attached")
	}

	prog := e.objs.profilePrograms.OnSample
	if prog == nil {
		return errors.New("BPF program OnSample is nil")
	}

	progFD := prog.FD()
	if progFD < 0 {
		return errors.New("invalid program FD")
	}

	err := e.createPerfEventsAndAttach(progFD, targetPID, samplingPeriodNs)
	if err != nil {
		return err
	}

	e.started = true
	return nil
}

func (e *ebpfProfiler) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.started {
		// still close objects
		_ = e.objs.Close()
		return nil
	}

	var resultErr error
	// disable and close perf fds
	for _, fd := range e.perfFDs {
		_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		if err := unix.Close(fd); err != nil {
			resultErr = fmt.Errorf("close perf fd: %w", err)
		}
	}
	e.perfFDs = nil
	e.started = false

	// close maps & programs
	if err := e.objs.Close(); err != nil && resultErr == nil {
		resultErr = fmt.Errorf("closing BPF objects: %w", err)
	}
	return resultErr
}

// reads and merges the per-CPU stackId -> counts map
func (e *ebpfProfiler) SnapshotCounts() (map[uint64]uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return nil, errors.New("profiler not started")
	}

	results := make(map[uint64]uint64)

	iter := e.objs.Counts.Iterate()
	var rawKey uint64

	numCPUs := runtime.NumCPU()
	perCpuVals := make([]uint64, numCPUs)

	for iter.Next(&rawKey, &perCpuVals) {
		var sum uint64
		for i := 0; i < numCPUs; i++ {
			sum += perCpuVals[i]
		}
		if sum > 0 {
			results[rawKey] = sum
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate counts map: %w", err)
	}

	return results, nil
}

// looks up the user frames and kernel frames by the corresponding stackIds
func (e *ebpfProfiler) LookupStacks(userID uint32, kernID uint32) ([]uint64, []uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return nil, nil, errors.New("profiler not started")
	}

	readFrames := func(id uint32) ([]uint64, error) {
		if id == missingSentinel {
			return nil, nil
		}

		var raw [maxStackFrames]uint64
		if err := e.objs.Stacks.Lookup(&id, &raw); err != nil {
			return nil, nil
		}
		// trim zeros
		n := 0
		for i, a := range raw {
			if a == 0 {
				n = i
				break
			}
			n = i + 1
		}
		frames := make([]uint64, n)
		copy(frames, raw[:n])
		return frames, nil
	}

	uFrames, err := readFrames(userID)
	if err != nil {
		return nil, nil, err
	}
	kFrames, err := readFrames(kernID)
	if err != nil {
		return uFrames, nil, err
	}
	return uFrames, kFrames, nil
}

func (e *ebpfProfiler) createPerfEventsAndAttach(progFD int, targetPID int, samplingPeriodNs uint64) error {
	numCPUs := runtime.NumCPU()
	pfds := make([]int, 0, numCPUs)

	for cpu := 0; cpu < numCPUs; cpu++ {
		attr := unix.PerfEventAttr{
			Type:        unix.PERF_TYPE_SOFTWARE,
			Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
			Sample:      uint64(samplingPeriodNs),
			Sample_type: unix.PERF_SAMPLE_IP,
		}

		fd, err := unix.PerfEventOpen(&attr, targetPID, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			// cleanup already opened fds
			for _, ofd := range pfds {
				unix.Close(ofd)
			}
			return fmt.Errorf("perf_event_open pid=%d cpu=%d: %w", targetPID, cpu, err)
		}

		// now attach the BPF prog
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, progFD); err != nil {
			unix.Close(fd)
			for _, ofd := range pfds {
				unix.Close(ofd)
			}
			return fmt.Errorf("ioctl PERF_EVENT_IOC_SET_BPF: %w", err)
		}

		// and enable the event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			unix.Close(fd)
			for _, ofd := range pfds {
				unix.Close(ofd)
			}
			return fmt.Errorf("ioctl PERF_EVENT_IOC_ENABLE: %w", err)
		}

		pfds = append(pfds, fd)
	}
	e.perfFDs = pfds
	return nil
}

func unpackKey(key uint64) (userID, kernID uint32) {
	userID = uint32(key >> 32)
	kernID = uint32(key & 0xffffffff)
	return
}
