package dsig_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

func FuzzSignAndVerifyHMAC(f *testing.F) {
	f.Add([]byte(`hello world`))
	f.Add([]byte(`{"key":"value"}`))
	f.Add([]byte(``))
	f.Add([]byte(`The true sign of intelligence is not knowledge but imagination.`))

	key := []byte("fuzz-hmac-secret-key-1234567890")

	f.Fuzz(func(t *testing.T, payload []byte) {
		sig, err := dsig.Sign(key, dsig.HMACWithSHA256, payload, nil)
		require.NoError(t, err)
		require.NoError(t, dsig.Verify(key, dsig.HMACWithSHA256, payload, sig))
	})
}

func FuzzSignAndVerifyRSA(f *testing.F) {
	f.Add([]byte(`hello world`))
	f.Add([]byte(`{"key":"value"}`))
	f.Add([]byte(``))
	f.Add([]byte(`The true sign of intelligence is not knowledge but imagination.`))

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		sig, err := dsig.Sign(priv, dsig.RSAPKCS1v15WithSHA256, payload, nil)
		require.NoError(t, err)
		require.NoError(t, dsig.Verify(&priv.PublicKey, dsig.RSAPKCS1v15WithSHA256, payload, sig))
	})
}

func FuzzSignAndVerifyECDSA(f *testing.F) {
	f.Add([]byte(`hello world`))
	f.Add([]byte(`{"key":"value"}`))
	f.Add([]byte(``))
	f.Add([]byte(`The true sign of intelligence is not knowledge but imagination.`))

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		sig, err := dsig.Sign(priv, dsig.ECDSAWithP256AndSHA256, payload, nil)
		require.NoError(t, err)
		require.NoError(t, dsig.Verify(&priv.PublicKey, dsig.ECDSAWithP256AndSHA256, payload, sig))
	})
}

func FuzzSignAndVerifyEdDSA(f *testing.F) {
	f.Add([]byte(`hello world`))
	f.Add([]byte(`{"key":"value"}`))
	f.Add([]byte(``))
	f.Add([]byte(`The true sign of intelligence is not knowledge but imagination.`))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		sig, err := dsig.Sign(priv, dsig.EdDSA, payload, nil)
		require.NoError(t, err)
		require.NoError(t, dsig.Verify(pub, dsig.EdDSA, payload, sig))
	})
}

func FuzzUnpackASN1ECDSASignature(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`not-asn1`))
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}) // minimal valid ASN.1 SEQUENCE{INTEGER(1), INTEGER(1)}

	f.Fuzz(func(_ *testing.T, data []byte) {
		var r, s big.Int
		_ = dsig.UnpackASN1ECDSASignature(data, &r, &s)
	})
}
