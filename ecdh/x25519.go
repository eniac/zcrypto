package ecdh

import (
	"golang.org/x/crypto/curve25519"
	"io"
	"math/big"
)

type x25519 struct {
	Curve
}

func X25519() Curve {
	return &x25519{}
}

func (e *x25519) GenerateKey(rand io.Reader) (*ECDHPrivateKey, *ECDHPublicKey, error) {
	var pub, priv [32]byte
	var err error

	_, err = io.ReadFull(rand, priv[:])
	if err != nil {
		return nil, nil, err
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	x := new(big.Int)
	x.SetBytes(pub[:])

	return &ECDHPrivateKey{D: priv[:]}, &ECDHPublicKey{X: x}, nil
}

func (e *x25519) Marshal(pub *ECDHPublicKey, compress bool) []byte {
	ret := new([32]byte)
	copy(ret[:], pub.X.Bytes())
	return ret[:]
}

func (e *x25519) Unmarshal(data []byte) (*ECDHPublicKey, bool) {

	x := new(big.Int)

	if len(data) == 33 && data[0] == 0x41 {
		x.SetBytes(data[1:33])
	} else if len(data) == 32 {
		x.SetBytes(data[0:32])
	} else {
		return nil, false
	}

	return &ECDHPublicKey{X: x}, true
}

func (e *x25519) GenerateSharedSecret(privKey *ECDHPrivateKey, pubKey *ECDHPublicKey) ([]byte, error) {

	pub := new([32]byte)
	priv := new([32]byte)
	secret := new([32]byte)

	copy(pub[:], pubKey.X.Bytes())
	copy(priv[:], privKey.D)

	curve25519.ScalarMult(secret, priv, pub)
	return secret[:], nil
}
