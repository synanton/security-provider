package authn

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/synanton/security-provider/internal/testcert"
)

// tlsState builds a client-side connection state carrying leaf as the
// verified peer chain. Verification itself is exercised by the adapter.
func tlsState(t *testing.T, ca *testcert.CA, leaf tls.Certificate) tls.ConnectionState {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	return tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf.Leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf.Leaf, ca.Cert}},
	}
}
