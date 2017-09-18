package ecdh

import (
	curve448 "git.schwanenlied.me/yawning/x448.git"
	"io"
	"math/big"
)

type x448 struct {
	Curve
}

func X448() Curve {
	return &x448{}
}

func (e *x448) GenerateKey(rand io.Reader) (*ECDHPrivateKey, *ECDHPublicKey, error) {
	var pub, priv [56]byte
	var err error

	_, err = io.ReadFull(rand, priv[:])
	if err != nil {
		return nil, nil, err
	}

	priv[0] &= 252
	priv[55] |= 128

	curve448.ScalarBaseMult(&pub, &priv)

	x := new(big.Int)
	x.SetBytes(pub[:])

	return &ECDHPrivateKey{D: priv[:]}, &ECDHPublicKey{X: x}, nil
}

func (e *x448) Marshal(pub *ECDHPublicKey, compress bool) []byte {
	ret := new([56]byte)
	copy(ret[:], pub.X.Bytes())
	return ret[:]
}

func (e *x448) Unmarshal(data []byte) (*ECDHPublicKey, bool) {

	x := new(big.Int)

	if len(data) == 57 && data[0] == 0x41 {
		x.SetBytes(data[1:57])
	} else if len(data) == 56 {
		x.SetBytes(data[0:56])
	} else {
		return nil, false
	}

	return &ECDHPublicKey{X: x}, true
}

func (e *x448) GenerateSharedSecret(privKey *ECDHPrivateKey, pubKey *ECDHPublicKey) ([]byte, error) {

	pub := new([56]byte)
	priv := new([56]byte)
	secret := new([56]byte)

	copy(pub[:], pubKey.X.Bytes())
	copy(priv[:], privKey.D)

	curve448.ScalarMult(secret, priv, pub)
	return secret[:], nil
}
