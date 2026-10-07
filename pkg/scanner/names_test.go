package scanner

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestResolveNamesThreadSafety(t *testing.T) {
	// Concurrent invocations to ensure no data races occur under -race detector
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = ResolveNames(ctx, "127.0.0.1", 100*time.Millisecond)
		}(i)
	}

	wg.Wait()
}
