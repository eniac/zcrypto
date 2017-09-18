// Support for short Weierstrass elliptic curves
// http://www.secg.org/SEC2-Ver-1.0.pdf
package ecdh

import (
	"crypto/elliptic"
	"github.com/keybase/go-crypto/brainpool"
	"io"
	"math/big"
)

type weierstrass struct {
	Curve
	curve elliptic.Curve
}

func NewWeierstrass(curve elliptic.Curve) Curve {
	return &weierstrass{
		curve: curve,
	}
}

func (e *weierstrass) GenerateKey(rand io.Reader) (*ECDHPrivateKey, *ECDHPublicKey, error) {
	var d []byte
	var x, y *big.Int
	var err error

	d, x, y, err = elliptic.GenerateKey(e.curve, rand)
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

func (e *weierstrass) Marshal(pub *ECDHPublicKey, compress bool) []byte {
	if compress {
		byteLen := (e.curve.Params().BitSize + 7) >> 3

		ret := make([]byte, 1+byteLen)
		ret[0] = byte(2 + pub.Y.Bit(e.curve.Params().BitSize)) // compressed point

		xBytes := pub.X.Bytes()
		copy(ret[1+byteLen-len(xBytes):], xBytes)
		return ret
	} else {
		return elliptic.Marshal(e.curve, pub.X, pub.Y)
	}
}

func (e *weierstrass) Unmarshal(data []byte) (*ECDHPublicKey, bool) {
	var key *ECDHPublicKey
	var x, y *big.Int
	// TODO: handle compressed points

	x, y = elliptic.Unmarshal(e.curve, data)
	if x == nil || y == nil {
		return key, false
	}
	key = &ECDHPublicKey{
		X: x,
		Y: y,
	}
	return key, true
}

func (e *weierstrass) GenerateSharedSecret(privKey *ECDHPrivateKey, pubKey *ECDHPublicKey) ([]byte, error) {
	x, _ := e.curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D)
	return x.Bytes(), nil
}

var (
	p160k1, p160r1, p160r2, p192k1, p192r1, p224k1, p256k1 *elliptic.CurveParams
)

func initP160r1() {
	p160r1 = new(elliptic.CurveParams)
	p160r1.P, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffff7fffffff", 16)
	p160r1.N, _ = new(big.Int).SetString("0100000000000000000001f4c8f927aed3ca752257", 16)
	p160r1.B, _ = new(big.Int).SetString("1c97befc54bd7a8b65acf89f81d4d4adc565fa45", 16)
	p160r1.Gx, _ = new(big.Int).SetString("4a96b5688ef573284664698968c38bb913cbfc82", 16)
	p160r1.Gy, _ = new(big.Int).SetString("23a628553168947d59dcc912042351377ac5fb32", 16)
	p160r1.BitSize = 160
}

func initP160r2() {
	p160r2 = new(elliptic.CurveParams)
	p160r2.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16)
	p160r2.N, _ = new(big.Int).SetString("0100000000000000000000351EE786A818F3A1A16B", 16)
	p160r2.B, _ = new(big.Int).SetString("B4E134D3FB59EB8BAB57274904664D5AF50388BA", 16)
	p160r2.Gx, _ = new(big.Int).SetString("52DCB034293A117E1F4FF11B30F7199D3144CE6D", 16)
	p160r2.Gy, _ = new(big.Int).SetString("FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E", 16)
	p160r2.BitSize = 160
}

func initP192r1() {
	p192r1 = new(elliptic.CurveParams)
	p192r1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
	p192r1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
	p192r1.B, _ = new(big.Int).SetString("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
	p192r1.Gx, _ = new(big.Int).SetString("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16)
	p192r1.Gy, _ = new(big.Int).SetString("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
	p192r1.BitSize = 192
}

func P160r1() Curve {
	initP160r1()
	return NewWeierstrass(p160r1)
}

func P160r2() Curve {
	initP160r2()
	return NewWeierstrass(p160r2)
}

func P192r1() Curve {
	initP192r1()
	return NewWeierstrass(p192r1)
}

func P224r1() Curve {
	return NewWeierstrass(elliptic.P224())
}

func P256r1() Curve {
	return NewWeierstrass(elliptic.P256())
}

func P384r1() Curve {
	return NewWeierstrass(elliptic.P384())
}

func P521r1() Curve {
	return NewWeierstrass(elliptic.P521())
}

func BrainpoolP256r1() Curve {
	return NewWeierstrass(brainpool.P256r1())
}

func BrainpoolP384r1() Curve {
	return NewWeierstrass(brainpool.P384r1())
}

func BrainpoolP512r1() Curve {
	return NewWeierstrass(brainpool.P512r1())
}

func BrainpoolP256t1() Curve {
	return NewWeierstrass(brainpool.P256t1())
}

func BrainpoolP384t1() Curve {
	return NewWeierstrass(brainpool.P384t1())
}

func BrainpoolP512t1() Curve {
	return NewWeierstrass(brainpool.P512t1())
}
