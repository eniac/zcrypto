// Support for binary elliptic curves
// http://www.secg.org/SEC2-Ver-1.0.pdf
package ecdh

import (
	"crypto/elliptic"
	"io"
	"math/big"
)

type binary struct {
	Curve
	curve elliptic.Curve
}

func NewBinary(curve elliptic.Curve) Curve {
	return &binary{
		curve: curve,
	}
}

func (e *binary) GenerateKey(rand io.Reader) (*ECDHPrivateKey, *ECDHPublicKey, error) {
	var d []byte
	var x, y *big.Int
	var err error

	//d, x, y, err = elliptic.GenerateKey(e.curve, rand)
	x, y = e.curve.Params().Gx, e.curve.Params().Gy

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

func (e *binary) Marshal(pub *ECDHPublicKey, compress bool) []byte {
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

func (e *binary) Unmarshal(data []byte) (*ECDHPublicKey, bool) {
	var key *ECDHPublicKey
	var x, y *big.Int
	// TODO: handle compressed points

	//x, y = elliptic.Unmarshal(e.curve, data)
	byteLen := (e.curve.Params().BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		return key, false
	}
	if data[0] != 4 { // uncompressed form
		return key, false
	}
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	//if !curve.IsOnCurve(x, y) {
	//    x, y = nil, nil
	//}

	if x == nil || y == nil {
		return key, false
	}
	key = &ECDHPublicKey{
		X: x,
		Y: y,
	}
	return key, true
}

func (e *binary) GenerateSharedSecret(privKey *ECDHPrivateKey, pubKey *ECDHPublicKey) ([]byte, error) {
	//x, _ := e.curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D)
	x := pubKey.X
	return x.Bytes(), nil
}

var (
	t163k1, t163r1, t163r2 *elliptic.CurveParams
)

func initT163k1() {
	t163k1 = new(elliptic.CurveParams)
	t163k1.P, _ = new(big.Int).SetString("", 16)
	t163k1.N, _ = new(big.Int).SetString("", 16)
	t163k1.B, _ = new(big.Int).SetString("", 16)
	t163k1.Gx, _ = new(big.Int).SetString("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8", 16)
	t163k1.Gy, _ = new(big.Int).SetString("0289070FB05D38FF58321F2E800536D538CCDAA3D9", 16)
	t163k1.BitSize = 163
}

func initT163r1() {
	t163r1 = new(elliptic.CurveParams)
	t163r1.P, _ = new(big.Int).SetString("", 16)
	t163r1.N, _ = new(big.Int).SetString("", 16)
	t163r1.B, _ = new(big.Int).SetString("", 16)
	t163r1.Gx, _ = new(big.Int).SetString("0369979697AB43897789566789567F787A7876A654", 16)
	t163r1.Gy, _ = new(big.Int).SetString("00435EDB42EFAFB2989D51FEFCE3C80988F41FF883", 16)
	t163r1.BitSize = 163
}

func initT163r2() {
	t163r2 = new(elliptic.CurveParams)
	t163r2.P, _ = new(big.Int).SetString("", 16)
	t163r2.N, _ = new(big.Int).SetString("", 16)
	t163r2.B, _ = new(big.Int).SetString("", 16)
	t163r2.Gx, _ = new(big.Int).SetString("03F0EBA16286A2D57EA0991168D4994637E8343E36", 16)
	t163r2.Gy, _ = new(big.Int).SetString("00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", 16)
	t163r2.BitSize = 163
}

func T163k1() Curve {
	initT163k1()
	return NewBinary(t163k1)
}

func T163r1() Curve {
	initT163r1()
	return NewBinary(t163r1)
}

func T163r2() Curve {
	initT163r2()
	return NewBinary(t163r2)
}
