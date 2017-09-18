// Support for Koblitz elliptic curves
// http://www.secg.org/SEC2-Ver-1.0.pdf
package ecdh

import (
	"github.com/zmap/zcrypto/ecdh/bitelliptic"
	"io"
	"math/big"
)

type koblitz struct {
	Curve
	curve *bitelliptic.BitCurve
}

func NewKoblitz(curve *bitelliptic.BitCurve) Curve {
	return &koblitz{
		curve: curve,
	}
}

func (e *koblitz) GenerateKey(rand io.Reader) (*ECDHPrivateKey, *ECDHPublicKey, error) {
	var d []byte
	var x, y *big.Int
	var err error

	d, x, y, err = e.curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	priv := &ECDHPrivateKey{
		D: d,
	}

	pub := &ECDHPublicKey{
		X: x,
		Y: y,
	}

	return priv, pub, nil
}

func (e *koblitz) Marshal(pub *ECDHPublicKey, compress bool) []byte {
	if compress {
		byteLen := (e.curve.BitSize + 7) >> 3

		ret := make([]byte, 1+byteLen)
		ret[0] = byte(2 + pub.Y.Bit(e.curve.BitSize)) // compressed point

		xBytes := pub.X.Bytes()
		copy(ret[1+byteLen-len(xBytes):], xBytes)
		return ret
	} else {
		return e.curve.Marshal(pub.X, pub.Y)
	}
}

func (e *koblitz) Unmarshal(data []byte) (*ECDHPublicKey, bool) {
	var key *ECDHPublicKey
	var x, y *big.Int
	// TODO: handle compressed points

	x, y = e.curve.Unmarshal(data)
	if x == nil || y == nil {
		return key, false
	}
	key = &ECDHPublicKey{
		X: x,
		Y: y,
	}
	return key, true
}

func (e *koblitz) GenerateSharedSecret(privKey *ECDHPrivateKey, pubKey *ECDHPublicKey) ([]byte, error) {
	x, _ := e.curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D)
	return x.Bytes(), nil
}

func P160k1() Curve {
	return NewKoblitz(bitelliptic.S160())
}

func P192k1() Curve {
	return NewKoblitz(bitelliptic.S192())
}

func P224k1() Curve {
	return NewKoblitz(bitelliptic.S224())
}

func P256k1() Curve {
	return NewKoblitz(bitelliptic.S256())
}
