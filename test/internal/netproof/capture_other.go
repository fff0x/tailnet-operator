//go:build !linux

package netproof

import "context"

func Capture(context.Context) (Snapshot, error) { return Snapshot{}, ErrUnsupported }
func CheckExternal(context.Context) Dials       { return Dials{IPv4: OtherFailure, IPv6: OtherFailure} }
