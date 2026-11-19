//go:build !windows

package wgbridge

import "golang.zx2c4.com/wireguard/conn"

func newPlatformBind() conn.Bind {
	return conn.NewDefaultBind()
}
