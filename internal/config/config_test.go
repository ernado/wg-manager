package config

import (
	"bytes"
	"net"
	"testing"
	"text/template"

	"github.com/go-faster/sdk/gold"
	"github.com/stretchr/testify/require"
)

func parseNet(t *testing.T, s string) net.IPNet {
	t.Helper()

	_, n, err := net.ParseCIDR(s)
	require.NoError(t, err)
	return *n
}

func TestConfigTemplate(t *testing.T) {
	tmpl := template.New("config")
	tmpl, err := tmpl.Parse(Template)
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	cfg := Config{
		Peers: []Peer{
			{
				AllowedIPs: parseNet(t, "10.5.5.2/32"),
			},
			{
				AllowedIPs: parseNet(t, "10.5.5.3/32"),
			},
		},
	}
	require.NoError(t, tmpl.Execute(buf, cfg))

	gold.Str(t, buf.String(), "wg0.conf")
}
