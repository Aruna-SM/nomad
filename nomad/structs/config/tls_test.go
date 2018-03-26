package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLSConfig_Merge(t *testing.T) {
	assert := assert.New(t)
	a := &TLSConfig{
		CAFile:   "test-ca-file",
		CertFile: "test-cert-file",
	}

	b := &TLSConfig{
		EnableHTTP:           true,
		EnableRPC:            true,
		VerifyServerHostname: true,
		CAFile:               "test-ca-file-2",
		CertFile:             "test-cert-file-2",
		RPCUpgradeMode:       true,
	}

	new := a.Merge(b)
	assert.Equal(b, new)
}

func TestTLS_CertificateInfoIsEqual_TrueWhenEmpty(t *testing.T) {
	assert := assert.New(t)
	a := &TLSConfig{}
	b := &TLSConfig{}
	assert.True(a.CertificateInfoIsEqual(b))
}

func TestTLS_CertificateInfoIsEqual_FalseWhenUnequal(t *testing.T) {
	const (
		cafile   = "../../../helper/tlsutil/testdata/ca.pem"
		foocert  = "../../../helper/tlsutil/testdata/nomad-foo.pem"
		fookey   = "../../../helper/tlsutil/testdata/nomad-foo-key.pem"
		foocert2 = "../../../helper/tlsutil/testdata/nomad-bad.pem"
		fookey2  = "../../../helper/tlsutil/testdata/nomad-bad-key.pem"
	)

	// Assert that both mismatching certificate and key files are considered
	// unequal
	{
		assert := assert.New(t)
		a := &TLSConfig{
			CAFile:   cafile,
			CertFile: foocert,
			KeyFile:  fookey,
		}
		b := &TLSConfig{
			CAFile:   cafile,
			CertFile: foocert2,
			KeyFile:  fookey2,
		}
		assert.False(a.CertificateInfoIsEqual(b))
	}

	// Assert that mismatching certificate are considered unequal
	{
		assert := assert.New(t)
		a := &TLSConfig{
			CAFile:   cafile,
			CertFile: foocert,
			KeyFile:  fookey,
		}
		b := &TLSConfig{
			CAFile:   cafile,
			CertFile: foocert2,
			KeyFile:  fookey,
		}
		assert.False(a.CertificateInfoIsEqual(b))
	}

	// Assert that mismatching keys are considered unequal
	{
		assert := assert.New(t)
		a := &TLSConfig{
			CAFile:   cafile,
			CertFile: foocert,
			KeyFile:  fookey,
		}
		b := &TLSConfig{
			CAFile:   cafile,
			CertFile: foocert,
			KeyFile:  fookey2,
		}
		assert.False(a.CertificateInfoIsEqual(b))
	}
}

func TestTLS_CertificateInfoIsEqual_TrueWhenEqual(t *testing.T) {
	const (
		cafile  = "../../../helper/tlsutil/testdata/ca.pem"
		foocert = "../../../helper/tlsutil/testdata/nomad-foo.pem"
		fookey  = "../../../helper/tlsutil/testdata/nomad-foo-key.pem"
	)
	assert := assert.New(t)
	a := &TLSConfig{
		CAFile:   cafile,
		CertFile: foocert,
		KeyFile:  fookey,
	}
	b := &TLSConfig{
		CAFile:   cafile,
		CertFile: foocert,
		KeyFile:  fookey,
	}
	assert.True(a.CertificateInfoIsEqual(b))
}

func TestTLS_Copy(t *testing.T) {
	assert := assert.New(t)
	a := &TLSConfig{CAFile: "abc", CertFile: "def", KeyFile: "ghi"}
	aCopy := a.Copy()
	assert.True(a.CertificateInfoIsEqual(aCopy))
}

// GetKeyLoader should always return an initialized KeyLoader for a TLSConfig
// object
func TestTLS_GetKeyloader(t *testing.T) {
	assert := assert.New(t)
	a := &TLSConfig{}
	assert.NotNil(a.GetKeyLoader())
}
