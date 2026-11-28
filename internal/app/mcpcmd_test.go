package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/nlink-jp/mcptool/serve"
)

// SIGINT and SIGTERM end the MCP server through its ctx, even while stdin is
// still open: the signal's ctx is what Serve gets (server-migration §2), and
// both are registered (mcptool's serve.Run, ADR-0002). Served on
// context.Background(), a signal killed the process instead, and this waits
// in vain.
func TestASignalEndsTheMCPServer(t *testing.T) {
	isolate(t)
	defer func(orig func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)) {
		serve.NotifyContext = orig
	}(serve.NotifyContext)
	var registered []os.Signal
	serve.NotifyContext = func(parent context.Context, sigs ...os.Signal) (context.Context, context.CancelFunc) {
		registered = sigs
		ctx, cancel := context.WithCancel(parent)
		go func() { time.Sleep(100 * time.Millisecond); cancel() }() // the signal arrives
		return ctx, cancel
	}
	inR, inW := io.Pipe()
	defer func() { _ = inW.Close() }()
	done := make(chan int, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- run([]string{"mcp"}, "dev", inR, &stdout, &stderr)
	}()
	select {
	case code := <-done:
		if code != exitOK {
			t.Errorf("exit code = %d, want %d", code, exitOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the MCP server did not end on the signal")
	}
	for _, want := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		if !slices.Contains(registered, want) {
			t.Errorf("%v is not among the signals that end the server: %v", want, registered)
		}
	}
}
