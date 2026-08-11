package net

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrivateIP(t *testing.T) {
	assert.True(t, IsPrivateIP(net.ParseIP("127.0.0.1")))
	assert.True(t, IsPrivateIP(net.ParseIP("10.0.0.5")))
	assert.True(t, IsPrivateIP(net.ParseIP("172.16.0.1")))
	assert.True(t, IsPrivateIP(net.ParseIP("192.168.1.1")))
	assert.True(t, IsPrivateIP(net.ParseIP("169.254.169.254")))
	assert.True(t, IsPrivateIP(net.ParseIP("::1")))

	assert.False(t, IsPrivateIP(net.ParseIP("8.8.8.8")))
	assert.False(t, IsPrivateIP(net.ParseIP("1.1.1.1")))
}

func TestValidateVEXURL_SchemeAndSSRF(t *testing.T) {
	// Reject non-HTTPS
	_, err := ValidateVEXURL("http://packages.wolfi.dev/os/security.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only https is permitted")

	// Reject metadata / loopback IP directly
	_, err = ValidateVEXURL("https://169.254.169.254/latest/meta-data/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted private IP target")

	_, err = ValidateVEXURL("https://127.0.0.1/sec.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted private IP target")
}
