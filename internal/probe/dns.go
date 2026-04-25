package probe

import (
	"context"
	"net"
	"strings"
)

// ReverseDNS does a PTR lookup for ip and returns the first result, with the
// trailing dot trimmed. Returns "" on timeout, no result, or any error.
func ReverseDNS(ctx context.Context, ip string) string {
	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
