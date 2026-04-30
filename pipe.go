package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Bidirectionally copy between a and b with a sliding idle timeout.
// Uses TCP half-close (CloseWrite) when one direction completes so the
// reverse direction can still drain.
func PipeConns(a, b net.Conn, idle time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyIdle(b, a, idle)
		halfClose(b)
	}()
	go func() {
		defer wg.Done()
		copyIdle(a, b, idle)
		halfClose(a)
	}()
	wg.Wait()
	a.Close()
	b.Close()
}

func halfClose(c net.Conn) {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		_ = x.CloseWrite()
		return
	}
	_ = c.Close()
}

// copyIdle copies src→dst, resetting src's read deadline before each Read so
// idle connections are killed but active transfers are not.
func copyIdle(dst io.Writer, src net.Conn, idle time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}
