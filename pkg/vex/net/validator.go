package net

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Private/Internal IP networks to block (SSRF Prevention)
var privateIPBlocks []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 Loopback
		"10.0.0.0/8",     // RFC1918 Private
		"172.16.0.0/12",  // RFC1918 Private
		"192.168.0.0/16", // RFC1918 Private
		"169.254.0.0/16", // Link-Local / Cloud Metadata (169.254.169.254)
		"0.0.0.0/8",      // Current network
		"240.0.0.0/4",    // Reserved
		"::1/128",        // IPv6 Loopback
		"fc00::/7",       // IPv6 Unique Local
		"fe80::/10",      // IPv6 Link Local
	}
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPBlocks = append(privateIPBlocks, block)
		}
	}
}

// IsPrivateIP returns true if the IP address falls within loopback, RFC1918, or cloud metadata ranges.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateVEXURL parses and validates a VEX feed URL for scheme and SSRF safety.
func ValidateVEXURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	// Enforce https://
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme %q: only https is permitted for security", u.Scheme)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("URL hostname cannot be empty")
	}

	// If hostname is an IP string directly
	if ip := net.ParseIP(hostname); ip != nil {
		if IsPrivateIP(ip) {
			return nil, fmt.Errorf("SSRF protection: restricted private IP target %s", hostname)
		}
		return u, nil
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname %s: %w", hostname, err)
	}

	for _, ip := range ips {
		if IsPrivateIP(ip) {
			return nil, fmt.Errorf("SSRF protection: hostname %s resolves to restricted private IP %s", hostname, ip.String())
		}
	}

	return u, nil
}

// NewSecureHTTPClient returns an http.Client configured with SSRF redirect guards.
func NewSecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Re-validate destination URL on redirect hop
			if _, err := ValidateVEXURL(req.URL.String()); err != nil {
				return fmt.Errorf("redirect target blocked for security: %w", err)
			}
			return nil
		},
	}
}
