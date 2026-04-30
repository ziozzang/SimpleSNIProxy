// SimpleSNIProxy — Go-based SNI/HTTP proxy with IPv6, DNS64 and DPI-evasion
// (TCP-level fragmentation, SNI-position split, HTTP Host obfuscation).
//
// Originally by Jioh L. Jung <ziozzang@gmail.com>.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	cfg, err := ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}

	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	dialer, err := NewDialer(cfg)
	if err != nil {
		slog.Error("dialer init", "err", err)
		os.Exit(1)
	}
	proxy := NewProxy(cfg, dialer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	var listeners []net.Listener

	startListener := func(addr string, port int, handler func(context.Context, net.Conn)) error {
		if port <= 0 {
			return nil
		}
		network := "tcp"
		if ip := net.ParseIP(addr); ip != nil {
			if ip.To4() == nil {
				network = "tcp6"
			} else {
				network = "tcp4"
			}
		}
		lc := net.ListenConfig{}
		l, err := lc.Listen(ctx, network, net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
		slog.Info("listening", "network", network, "addr", l.Addr().String())
		wg.Add(1)
		go func() {
			defer wg.Done()
			acceptLoop(ctx, l, handler, proxy)
		}()
		return nil
	}

	for _, b := range cfg.BindAddrs {
		if err := startListener(b, cfg.HTTPPort, proxy.HandleHTTP); err != nil {
			slog.Warn("HTTP listener", "bind", b, "err", err)
		}
		if err := startListener(b, cfg.HTTPSPort, proxy.HandleHTTPS); err != nil {
			slog.Warn("HTTPS listener", "bind", b, "err", err)
		}
	}

	if len(listeners) == 0 {
		slog.Error("no listeners started")
		os.Exit(1)
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	slog.Info("shutdown initiated", "signal", sig.String())
	cancel()
	for _, l := range listeners {
		_ = l.Close()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		slog.Warn("shutdown timed out")
	}
}

func acceptLoop(ctx context.Context, l net.Listener, handler func(context.Context, net.Conn), p *Proxy) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			slog.Warn("accept", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go handler(ctx, conn)
	}
}
