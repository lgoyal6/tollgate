package store

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
)

// This file is the gateway's only opinion about which upstream targets a
// route may point at, and it is a short one.
//
// The whole reason this gateway exists is that it holds somebody's real
// provider credential and injects it on the way out. That makes a route a
// loaded object: whoever chooses the upstream chooses where a credential and
// a request from inside the deployment's network get sent. On a cloud
// instance the sharpest version of that is the instance metadata endpoint,
// which answers to anything that can reach it, with the machine's own role
// credentials, over plain HTTP and with no authentication at all.
//
// What is deliberately NOT refused: RFC 1918, carrier NAT and loopback. The
// compose stack in this repo proxies to a demo upstream on localhost, the
// kind deployment proxies to pods on a private network, and the whole
// self-hosted story is somebody running this in front of their own
// infrastructure. A guard that refused private addresses would break every
// one of those and teach the first person who hit it to turn the guard off,
// which is worse than not having it.

// linkLocalV4 is 169.254.0.0/16: IPv4 link-local, and the address every major
// cloud answers instance metadata on.
var linkLocalV4 = netip.MustParsePrefix("169.254.0.0/16")

// awsIMDSv6 is the fixed IPv6 address AWS answers IMDS on.
var awsIMDSv6 = netip.MustParseAddr("fd00:ec2::254")

// metadataNames are the hostnames that name a metadata service by definition
// rather than by accident. The bare name "metadata" is deliberately absent:
// it is a plausible internal service name, and refusing it would be guessing
// about somebody else's DNS.
var metadataNames = map[string]bool{
	"metadata.google.internal": true,
	"metadata.goog":            true,
}

// ForbiddenUpstream reports whether a route's upstream host is a cloud
// instance metadata endpoint, and why.
//
// host may carry a port and may be a bare hostname, a dotted-quad address, a
// bracketed IPv6 address, or one of the integer spellings of an IPv4 address
// that a C resolver still accepts: 169.254.169.254, 0xa9fea9fe and
// 2852039166 are the same host, and a check that only knew the first would be
// a check somebody works around by typing the third.
//
// It does not resolve names. A hostname whose DNS answer is a metadata
// address is not caught here, and cannot be: resolution happens in the
// dialer, and an answer that passes a check can change before the connection
// is made. That limitation is stated in docs/runbooks rather than papered
// over with a check that looks stronger than it is.
func ForbiddenUpstream(host string) (reason string, forbidden bool) {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return "", false
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	h = strings.Trim(h, "[]")

	if metadataNames[h] {
		return fmt.Sprintf("%s is a cloud instance metadata hostname", h), true
	}
	addr, ok := parseHostAddr(h)
	if !ok {
		return "", false
	}
	switch {
	case addr.Is4() && linkLocalV4.Contains(addr):
		return fmt.Sprintf("%s is in 169.254.0.0/16, the link-local range cloud instance metadata answers on", addr), true
	case addr == awsIMDSv6:
		return fmt.Sprintf("%s is the AWS instance metadata address over IPv6", addr), true
	case addr.Is6() && addr.IsLinkLocalUnicast():
		return fmt.Sprintf("%s is an IPv6 link-local address", addr), true
	}
	return "", false
}

// parseHostAddr reads the spellings of an address a resolver would accept.
func parseHostAddr(h string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.Unmap(), true
	}
	// The integer forms. inet_aton accepts a bare decimal, hex or octal
	// 32-bit value as an IPv4 address, so getaddrinfo does too, so the Go
	// dialer inherits it from the system resolver.
	n, ok := new(big.Int).SetString(strings.TrimPrefix(h, "0x"), integerBase(h))
	if !ok || n.Sign() < 0 || n.BitLen() > 32 {
		return netip.Addr{}, false
	}
	var quad [4]byte
	n.FillBytes(quad[:])
	return netip.AddrFrom4(quad), true
}

// integerBase reports which base an all-digits host is written in, following
// inet_aton: 0x is hex, a leading 0 is octal, anything else decimal.
func integerBase(h string) int {
	switch {
	case strings.HasPrefix(h, "0x"):
		return 16
	case len(h) > 1 && h[0] == '0':
		return 8
	default:
		return 10
	}
}
