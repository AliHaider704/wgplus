//go:build windows

package wgbridge

import (
	"errors"
	"io"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	wsaEacces      = windows.WSAEACCES
	wsaEaddrInUse  = windows.WSAEADDRINUSE
	wsaEconnReset  = windows.WSAECONNRESET
	wsaEconnAbort  = windows.WSAECONNABORTED
	wsaEnetReset   = windows.WSAENETRESET
)

// windowsResilientBind hardens wireguard-go's Windows UDP bind against two known Windows failure modes:
// 1) Ephemeral Open(0) failing when IPv6 collides with WSAEADDRINUSE or Hyper-V excluded ports (WSAEACCES).
// 2) Receive returning ICMP Port Unreachable (WSAECONNRESET/WSAECONNABORTED/WSAENETRESET) or io.ErrNoProgress,
//    which otherwise causes wireguard-go's RoutineReceiveIncoming goroutine to exit permanently.
type windowsResilientBind struct {
	inner conn.Bind
}

func newPlatformBind() conn.Bind {
	return &windowsResilientBind{inner: conn.NewDefaultBind()}
}

func isWindowsPortRetryable(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, wsaEaddrInUse) ||
		errors.Is(err, wsaEacces) ||
		errors.Is(err, syscall.Errno(10048)) ||
		errors.Is(err, syscall.Errno(10013))
}

func isWindowsTransientRecvErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, wsaEconnReset) ||
		errors.Is(err, wsaEconnAbort) ||
		errors.Is(err, wsaEnetReset) ||
		errors.Is(err, syscall.Errno(10054)) ||
		errors.Is(err, syscall.Errno(10053)) ||
		errors.Is(err, syscall.Errno(10052)) ||
		errors.Is(err, io.ErrNoProgress)
}

func (b *windowsResilientBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	maxAttempts := 1
	if port == 0 {
		maxAttempts = 16
	}

	var (
		fns        []conn.ReceiveFunc
		actualPort uint16
		err        error
	)
	for attempt := 0; attempt < maxAttempts; attempt++ {
		fns, actualPort, err = b.inner.Open(port)
		if err == nil {
			break
		}
		if port != 0 || !isWindowsPortRetryable(err) {
			return nil, 0, err
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		return nil, 0, err
	}

	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		origFn := fn
		wrapped[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			for {
				n, rErr := origFn(packets, sizes, eps)
				if rErr != nil && isWindowsTransientRecvErr(rErr) {
					continue
				}
				return n, rErr
			}
		}
	}
	return wrapped, actualPort, nil
}

func (b *windowsResilientBind) Close() error {
	return b.inner.Close()
}

func (b *windowsResilientBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

func (b *windowsResilientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

func (b *windowsResilientBind) BatchSize() int {
	return b.inner.BatchSize()
}

func (b *windowsResilientBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	return b.inner.Send(bufs, ep)
}
