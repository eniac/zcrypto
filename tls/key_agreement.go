// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
    "strings"

	"github.com/zmap/zcrypto/ecdh"
	"github.com/zmap/zcrypto/x509"
)

var errClientKeyExchange = errors.New("tls: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tls: invalid ServerKeyExchange message")
var errUnexpectedServerKeyExchange = errors.New("tls: unexpected ServerKeyExchange message")

// rsaKeyAgreement implements the standard TLS key agreement where the client
// encrypts the pre-master secret to the server's public key.
type rsaKeyAgreement struct {
	auth          keyAgreementAuthentication
	version       uint16
	clientVersion uint16
	ephemeral     bool
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	verifyError   error
}

func (ka *rsaKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	// Only send a server key agreement when the cipher is an RSA export
	// TODO: Make this a configuration parameter
	ka.clientVersion = clientHello.vers
	if !ka.ephemeral {
		return nil, nil
	}

	// Generate an ephemeral RSA key or use the one in the config
	if config.ExportRSAKey != nil {
		ka.privateKey = config.ExportRSAKey
	} else {
		key, err := rsa.GenerateKey(config.rand(), 512)
		if err != nil {
			return nil, err
		}
		ka.privateKey = key
	}

	// Serialize the key parameters to a nice byte array. The byte array can be
	// positioned later.
	modulus := ka.privateKey.N.Bytes()
	exponent := big.NewInt(int64(ka.privateKey.E)).Bytes()
	serverRSAParams := make([]byte, 0, 2+len(modulus)+2+len(exponent))
	serverRSAParams = append(serverRSAParams, byte(len(modulus)>>8), byte(len(modulus)))
	serverRSAParams = append(serverRSAParams, modulus...)
	serverRSAParams = append(serverRSAParams, byte(len(exponent)>>8), byte(len(exponent)))
	serverRSAParams = append(serverRSAParams, exponent...)

	return ka.auth.signParameters(config, cert, clientHello, hello, serverRSAParams)
}

func (ka *rsaKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg) ([]byte, error) {
	preMasterSecret := make([]byte, 48)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, err
	}

	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}

	ciphertext := ckx.ciphertext
	if ka.version != VersionSSL30 {
		ciphertextLen := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
		if ciphertextLen != len(ckx.ciphertext)-2 {
			return nil, errClientKeyExchange
		}
		ciphertext = ckx.ciphertext[2:]
	}

	key := ka.privateKey
	if key == nil {
		key = cert.PrivateKey.(*rsa.PrivateKey)
	}

	err = rsa.DecryptPKCS1v15SessionKey(config.rand(), key, ciphertext, preMasterSecret)
	if err != nil {
		return nil, err
	}
	// We don't check the version number in the premaster secret.  For one,
	// by checking it, we would leak information about the validity of the
	// encrypted pre-master secret. Secondly, it provides only a small
	// benefit against a downgrade attack and some implementations send the
	// wrong version anyway. See the discussion at the end of section
	// 7.4.7.1 of RFC 4346.
	return preMasterSecret, nil
}

func (ka *rsaKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if !ka.ephemeral {
		return nil
	}

	k := skx.key
	// Read the modulus
	if len(k) < 2 {
		return errServerKeyExchange
	}
	modulusLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < modulusLen {
		return errServerKeyExchange
	}
	modulus := new(big.Int).SetBytes(k[:modulusLen])
	k = k[modulusLen:]

	// Read the exponent
	if len(k) < 2 {
		return errServerKeyExchange
	}
	exponentLength := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < exponentLength || exponentLength > 4 {
		return errServerKeyExchange
	}
	rawExponent := k[0:exponentLength]
	exponent := 0
	for _, b := range rawExponent {
		exponent <<= 8
		exponent |= int(b)
	}
	ka.publicKey = new(rsa.PublicKey)
	ka.publicKey.E = exponent
	ka.publicKey.N = modulus

	paramsLen := 2 + exponentLength + 2 + modulusLen

	serverRSAParams := skx.key[:paramsLen]
	sig := skx.key[paramsLen:]

	ka.verifyError = ka.auth.verifyParameters(config, clientHello, serverHello, cert, serverRSAParams, sig)
	if config.InsecureSkipVerify {
		return nil
	}
	return ka.verifyError
}

func (ka *rsaKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}
	var publicKey *rsa.PublicKey
	if ka.publicKey != nil {
		publicKey = ka.publicKey
	} else {
		var ok bool
		publicKey, ok = cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errClientKeyExchange
		}
	}
	encrypted, err := rsa.EncryptPKCS1v15(config.rand(), publicKey, preMasterSecret)
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	var body []byte
	if ka.version != VersionSSL30 {
		ckx.ciphertext = make([]byte, len(encrypted)+2)
		ckx.ciphertext[0] = byte(len(encrypted) >> 8)
		ckx.ciphertext[1] = byte(len(encrypted))
		body = ckx.ciphertext[2:]
	} else {
		ckx.ciphertext = make([]byte, len(encrypted))
		body = ckx.ciphertext
	}
	copy(body, encrypted)
	return preMasterSecret, ckx, nil
}

// sha1Hash calculates a SHA1 hash over the given byte slices.
func md5Hash(slices [][]byte) []byte {
	h := md5.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// sha1Hash calculates a SHA1 hash over the given byte slices.
func sha1Hash(slices [][]byte) []byte {
	hsha1 := sha1.New()
	for _, slice := range slices {
		hsha1.Write(slice)
	}
	return hsha1.Sum(nil)
}

// md5SHA1Hash implements TLS 1.0's hybrid hash function which consists of the
// concatenation of an MD5 and SHA1 hash.
func md5SHA1Hash(slices [][]byte) []byte {
	md5sha1 := make([]byte, md5.Size+sha1.Size)
	hmd5 := md5.New()
	for _, slice := range slices {
		hmd5.Write(slice)
	}
	copy(md5sha1, hmd5.Sum(nil))
	copy(md5sha1[md5.Size:], sha1Hash(slices))
	return md5sha1
}

// sha224Hash implements TLS 1.2's hash function.
func sha224Hash(slices [][]byte) []byte {
	h := crypto.SHA224.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// sha256Hash implements TLS 1.2's hash function.
func sha256Hash(slices [][]byte) []byte {
	h := sha256.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// sha256Hash implements TLS 1.2's hash function.
func sha384Hash(slices [][]byte) []byte {
	h := crypto.SHA384.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// sha512Hash implements TLS 1.2's hash function.
func sha512Hash(slices [][]byte) []byte {
	h := sha512.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

// hashForServerKeyExchange hashes the given slices and returns their digest
// and the identifier of the hash function used. The hashFunc argument is only
// used for >= TLS 1.2 and precisely identifies the hash function to use.
func hashForServerKeyExchange(sigType, hashFunc uint8, version uint16, slices ...[]byte) ([]byte, crypto.Hash, error) {
	if version >= VersionTLS12 {
		switch hashFunc {
		case hashSHA512:
			return sha512Hash(slices), crypto.SHA512, nil
		case hashSHA384:
			return sha384Hash(slices), crypto.SHA384, nil
		case hashSHA256:
			return sha256Hash(slices), crypto.SHA256, nil
		case hashSHA224:
			return sha224Hash(slices), crypto.SHA224, nil
		case hashSHA1:
			return sha1Hash(slices), crypto.SHA1, nil
		case hashMD5:
			return md5Hash(slices), crypto.MD5, nil
		default:
			return nil, crypto.Hash(0), errors.New("tls: unknown hash function used by peer")
		}
	}
	if sigType == signatureECDSA || sigType == signatureDSA {
		return sha1Hash(slices), crypto.SHA1, nil
	}
	return md5SHA1Hash(slices), crypto.MD5SHA1, nil
}

// pickTLS12HashForSignature returns a TLS 1.2 hash identifier for signing a
// ServerKeyExchange given the signature type being used and the client's
// advertised list of supported signature and hash combinations.
func pickTLS12HashForSignature(sigType uint8, clientList, serverList []signatureAndHash) (uint8, error) {
	if len(clientList) == 0 {
		// If the client didn't specify any signature_algorithms
		// extension then we can assume that it supports SHA1. See
		// http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		return hashSHA1, nil
	}

	for _, sigAndHash := range clientList {
		if sigAndHash.signature != sigType {
			continue
		}
		if isSupportedSignatureAndHash(sigAndHash, serverList) {
			return sigAndHash.hash, nil
		}
	}

	return 0, errors.New("tls: client doesn't support any common hash functions")
}

func curveForCurveID(id CurveID) (ecdh.Curve, bool) {
	switch id {
	case CurveT163k1:
		return ecdh.T163k1(), true
	case CurveT163r1:
		return ecdh.T163r1(), true
	case CurveT163r2:
		return ecdh.T163r2(), true
	case CurveP160r1:
		return ecdh.P160r1(), true
	case CurveP160k1:
		return ecdh.P160k1(), true
	case CurveP160r2:
		return ecdh.P160r2(), true
	case CurveP192r1:
		return ecdh.P192r1(), true
	case CurveP192k1:
		return ecdh.P192k1(), true
	case CurveP224k1:
		return ecdh.P224k1(), true
	case CurveP224r1:
		return ecdh.P224r1(), true
	case CurveP256k1:
		return ecdh.P256k1(), true
	case CurveP256r1:
		return ecdh.P256r1(), true
	case CurveP384r1:
		return ecdh.P384r1(), true
	case CurveP521r1:
		return ecdh.P521r1(), true
	case CurveBrainpoolP256r1:
		return ecdh.BrainpoolP256r1(), true
	case CurveBrainpoolP384r1:
		return ecdh.BrainpoolP384r1(), true
	case CurveBrainpoolP512r1:
		return ecdh.BrainpoolP512r1(), true
	case Curve25519:
		return ecdh.X25519(), true
	case Curve448:
		return ecdh.X448(), true
	default:
		return nil, false
	}
}

// keyAgreementAuthentication is a helper interface that specifies how
// to authenticate the ServerKeyExchange parameters.
type keyAgreementAuthentication interface {
	signParameters(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg, params []byte) (*serverKeyExchangeMsg, error)
	verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) error
}

// nilKeyAgreementAuthentication does not authenticate the key
// agreement parameters.
type nilKeyAgreementAuthentication struct{}

func (ka *nilKeyAgreementAuthentication) signParameters(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg, params []byte) (*serverKeyExchangeMsg, error) {
	skx := new(serverKeyExchangeMsg)
	skx.key = params
	return skx, nil
}

func (ka *nilKeyAgreementAuthentication) verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) error {
	return nil
}

// signedKeyAgreement signs the ServerKeyExchange parameters with the
// server's private key.
type signedKeyAgreement struct {
	version uint16
	sigType uint8
	raw     []byte
	valid   bool
	sh      signatureAndHash
}

func (ka *signedKeyAgreement) signParameters(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg, params []byte) (*serverKeyExchangeMsg, error) {
	var tls12HashId uint8
	var err error
	if ka.version >= VersionTLS12 {
		if tls12HashId, err = pickTLS12HashForSignature(ka.sigType, clientHello.signatureAndHashes, config.signatureAndHashesForServer()); err != nil {
			return nil, err
		}
		ka.sh.hash = tls12HashId
	}
	ka.sh.signature = ka.sigType
	digest, hashFunc, err := hashForServerKeyExchange(ka.sigType, tls12HashId, ka.version, clientHello.random, hello.random, params)
	if err != nil {
		return nil, err
	}

	var sig []byte
	switch ka.sigType {
	case signatureECDSA:
		privKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ECDHE ECDSA requires an ECDSA server private key")
		}
		r, s, err := ecdsa.Sign(config.rand(), privKey, digest)
		if err != nil {
			return nil, errors.New("failed to sign ECDHE parameters: " + err.Error())
		}
		sig, err = asn1.Marshal(ecdsaSignature{r, s})
	case signatureRSA:
		privKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("ECDHE RSA requires a RSA server private key")
		}
		sig, err = rsa.SignPKCS1v15(config.rand(), privKey, hashFunc, digest)
		if err != nil {
			return nil, errors.New("failed to sign ECDHE parameters: " + err.Error())
		}
	default:
		return nil, errors.New("unknown ECDHE signature algorithm")
	}

	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(params)+sigAndHashLen+2+len(sig))
	copy(skx.key, params)
	k := skx.key[len(params):]
	if ka.version >= VersionTLS12 {
		k[0] = tls12HashId
		k[1] = ka.sigType
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)
	ka.raw = sig
	ka.valid = true // We (the server) signed
	return skx, nil
}

func (ka *signedKeyAgreement) verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) error {
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	var tls12HashId uint8
	if ka.version >= VersionTLS12 {
		// handle SignatureAndHashAlgorithm
		var sigAndHash []uint8
		sigAndHash, sig = sig[:2], sig[2:]
		tls12HashId = sigAndHash[0]
		ka.sh.hash = tls12HashId
		ka.sh.signature = sigAndHash[1]
		if sigAndHash[1] != ka.sigType {
			return errServerKeyExchange
		}
		if len(sig) < 2 {
			return errServerKeyExchange
		}

		if !isSupportedSignatureAndHash(signatureAndHash{ka.sigType, tls12HashId}, config.signatureAndHashesForClient()) {
			return errors.New("tls: unsupported hash function for ServerKeyExchange")
		}
	}
	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]
	ka.raw = sig

	digest, hashFunc, err := hashForServerKeyExchange(ka.sigType, tls12HashId, ka.version, clientHello.random, serverHello.random, params)
	if err != nil {
		return err
	}

	switch ka.sigType {
	case signatureECDSA:
		augECDSA, ok := cert.PublicKey.(*x509.AugmentedECDSA)
		pubKey := augECDSA.Pub
		if !ok {
			return errors.New("ECDHE ECDSA: could not covert cert.PublicKey to x509.AugmentedECDSA")
		}
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pubKey, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("ECDSA verification failure")
		}
	case signatureRSA:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("ECDHE RSA requires a RSA server public key")
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, digest, sig); err != nil {
			return err
		}
	case signatureDSA:
		pubKey, ok := cert.PublicKey.(*dsa.PublicKey)
		if !ok {
			return errors.New("DSS ciphers require a DSA server public key")
		}
		dsaSig := new(dsaSignature)
		if _, err := asn1.Unmarshal(sig, dsaSig); err != nil {
			return err
		}
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			return errors.New("DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pubKey, digest, dsaSig.R, dsaSig.S) {
			return errors.New("DSA verification failure")
		}
	default:
		return errors.New("unknown ECDHE signature algorithm")
	}
	ka.valid = true
	return nil
}

// ecdheRSAKeyAgreement implements a TLS key agreement where the server
// generates a ephemeral EC public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH. The signature may
// either be ECDSA or RSA.
type ecdheKeyAgreement struct {
	auth            keyAgreementAuthentication
	privateKey      *ecdh.ECDHPrivateKey
	serverPublicKey *ecdh.ECDHPublicKey
	clientPublicKey *ecdh.ECDHPublicKey
	curve           ecdh.Curve
	verifyError     error
	curveID         CurveID
	clientPrivKey []byte
	serverPrivKey []byte
	clientX       *big.Int
	clientY       *big.Int
}

func (ka *ecdheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	var curveid CurveID
	preferredCurves := config.curvePreferences()

NextCandidate:
	for _, candidate := range preferredCurves {
		for _, c := range clientHello.supportedCurves {
			if candidate == c {
				curveid = c
				break NextCandidate
			}
		}
	}

	if curveid == 0 {
		return nil, errors.New("tls: no supported elliptic curves offered")
	}
	ka.curveID = curveid

	var ok bool
	if ka.curve, ok = curveForCurveID(curveid); !ok {
		return nil, errors.New("tls: preferredCurves includes unsupported curve")
	}

	var pub *ecdh.ECDHPublicKey
	var err error
	ka.privateKey, pub, err = ka.curve.GenerateKey(config.rand())
	if err != nil {
		return nil, err
	}
	ecdhePublic := ka.curve.Marshal(pub, false)

	ka.serverPrivKey = make([]byte, len(ka.privateKey.D))
	copy(ka.serverPrivKey, ka.privateKey.D)

	// http://tools.ietf.org/html/rfc4492#section-5.4
	serverECDHParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHParams[0] = 3 // named curve
	serverECDHParams[1] = byte(curveid >> 8)
	serverECDHParams[2] = byte(curveid)
	serverECDHParams[3] = byte(len(ecdhePublic))
	copy(serverECDHParams[4:], ecdhePublic)

	return ka.auth.signParameters(config, cert, clientHello, hello, serverECDHParams)
}

func (ka *ecdheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, errClientKeyExchange
	}
	publicKey, ok := ka.curve.Unmarshal(ckx.ciphertext[1:])
	if !ok {
		return nil, errClientKeyExchange
	}
    ka.clientX, ka.clientY = publicKey.X, publicKey.Y

	preMasterSecret, err := ka.curve.GenerateSharedSecret(ka.privateKey, publicKey)
	if err != nil {
		return nil, err
	}

	return preMasterSecret, nil
}

func (ka *ecdheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	ka.curveID = CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	var ok bool
	if ka.curve, ok = curveForCurveID(ka.curveID); !ok {
		return errors.New("tls: server selected unsupported curve")
	}

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	ka.serverPublicKey, ok = ka.curve.Unmarshal(skx.key[4 : 4+publicLen])
	if !ok {
		return errServerKeyExchange
	}

	serverECDHParams := skx.key[:4+publicLen]

	sig := skx.key[4+publicLen:]
	ka.verifyError = ka.auth.verifyParameters(config, clientHello, serverHello, cert, serverECDHParams, sig)
	if config.InsecureSkipVerify {
		return nil
	}
	return ka.verifyError
}

func (ka *ecdheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	var err error
	var preMasterSecret []byte
	var mx, my *big.Int

	if ka.curve == nil {
		return nil, nil, errors.New("missing ServerKeyExchange message")
	}

	kexConfig := strings.Split(config.KexConfig, ",")

	compress := false
	staticKex := false
	for _, option := range kexConfig {
		switch option {
		case "COMPRESS":
			compress = true
		case "X25519_INVALID_S2":
			mx, _ = new(big.Int).SetString("0", 10)
			ka.curveID = Curve25519
			staticKex = true
		case "X25519_INVALID_S4":
			mx, _ = new(big.Int).SetString("1", 10)
			ka.curveID = Curve25519
			staticKex = true
		case "X25519_INVALID_S8":
			mx, _ = new(big.Int).SetString("39382357235489614581723060781553021112529911719440698176882885853963445705823", 10)
			ka.curveID = Curve25519
			staticKex = true
		case "X25519_TWIST_S4":
			mx, _ = new(big.Int).SetString("40037414119260815170158213804056845813451397265373646178320500467079007173856", 10)
			ka.curveID = Curve25519
			staticKex = true
		case "256_ECP_INVALID_S5": // NIST-P256 generator of subgroup of order 5 on curve w/ B-1
			mx, _ = new(big.Int).SetString("86765160823711241075790919525606906052464424178558764461827806608937748883041", 10)
			my, _ = new(big.Int).SetString("62096069626295534024197897036720226401219594482857127378802405572766226928611", 10)
			ka.curveID = CurveP256r1
			staticKex = true
		case "256_ECP_TWIST_S5": // NIST-P256 generator of subgroup of order 5 on twist
			// y^2 = x^3 + 64540953657701435357043644561909631465859193840763101878720769919119982834454*x + 21533133778103722695369883733312533132949737997864576898233410179589774724054
			//mx, _ = new(big.Int).SetString("75610932410248387784210576211184530780201393864652054865721797292564276389325", 10)
			//my, _ = new(big.Int).SetString("30046858919395540206086570437823256496220553255320964836453418613861962163895", 10)
			mx, _ = new(big.Int).SetString("65000580346672419638629453770715906531917592959616632823634978442784087859381", 10)
			my, _ = new(big.Int).SetString("101434952638835666830672287755036482040135206184891409299575619037815517987306", 10)
			ka.curveID = CurveP256r1
			staticKex = true
		case "256_ECP_TWIST_S5_SHARED": // x-coordinate corresponds to points both on the curve and the twist
			mx, _ = new(big.Int).SetString("75610932410248387784210576211184530780201393864652054865721797292564276389325", 10)
			my, _ = new(big.Int).SetString("17016988387429062713000967549338170748423683329322284176365945285736516510233", 10)
			ka.curveID = CurveP256r1
			staticKex = true
		case "224_ECP_INVALID_S13": // NIST-P224 generator of subgroup of order 13 on curve w/ B-1
			mx, _ = new(big.Int).SetString("1234919426772886915432358412587735557527373236174597031415308881584", 10)
			my, _ = new(big.Int).SetString("218592750580712164156183367176268299828628545379017213517316023994", 10)
			ka.curveID = CurveP224r1
			staticKex = true
		case "224_ECP_TWIST_S11": // NIST-P224 generator of subgroup of order 11 on twist
			mx, _ = new(big.Int).SetString("21219928721835262216070635629075256199931199995500865785214182108232", 10)
			my, _ = new(big.Int).SetString("2486431965114139990348241493232938533843075669604960787364227498903", 10)
			ka.curveID = CurveP224r1
			staticKex = true
		case "":
		default:
			panic("unrecognized tls-kex-config option")
		}
	}
	if staticKex {
		ka.curve, _ = curveForCurveID(ka.curveID)
		ka.privateKey = nil
		ka.clientPublicKey = &ecdh.ECDHPublicKey{
			X: mx,
			Y: my,
		}
		preMasterSecret = mx.Bytes() // set the premaster secret to a point in the subgroup
	} else {
		ka.privateKey, ka.clientPublicKey, err = ka.curve.GenerateKey(config.rand())
		if err != nil {
			return nil, nil, err
		}
		preMasterSecret, err = ka.curve.GenerateSharedSecret(ka.privateKey, ka.serverPublicKey)
		if err != nil {
			return nil, nil, err
		}
	}

	serialized := ka.curve.Marshal(ka.clientPublicKey, compress)

	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 1+len(serialized))
	ckx.ciphertext[0] = byte(len(serialized))
	copy(ckx.ciphertext[1:], serialized)

	return preMasterSecret, ckx, nil
}

// dheRSAKeyAgreement implements a TLS key agreement where the server generates
// an ephemeral Diffie-Hellman public/private key pair and signs it. The
// pre-master secret is then calculated using Diffie-Hellman.
type dheKeyAgreement struct {
	auth        keyAgreementAuthentication
	p, g        *big.Int
	yTheirs     *big.Int
	yOurs       *big.Int
	xOurs       *big.Int
	yServer     *big.Int
	yClient     *big.Int
	verifyError error
}

func (ka *dheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	var q *big.Int
	// 2048-bit MODP Group with 256-bit Prime Order Subgroup (RFC
	// 5114, Section 2.3)
	// TODO: Take a prime in the config
	ka.p, _ = new(big.Int).SetString("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16)
	ka.g, _ = new(big.Int).SetString("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16)
	q, _ = new(big.Int).SetString("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16)

	var err error
	ka.xOurs, err = rand.Int(config.rand(), q)
	if err != nil {
		return nil, err
	}
	yOurs := new(big.Int).Exp(ka.g, ka.xOurs, ka.p)
	ka.yOurs = yOurs
	ka.yServer = new(big.Int).Set(yOurs)

	// http://tools.ietf.org/html/rfc5246#section-7.4.3
	pBytes := ka.p.Bytes()
	gBytes := ka.g.Bytes()
	yBytes := yOurs.Bytes()
	serverDHParams := make([]byte, 0, 2+len(pBytes)+2+len(gBytes)+2+len(yBytes))
	serverDHParams = append(serverDHParams, byte(len(pBytes)>>8), byte(len(pBytes)))
	serverDHParams = append(serverDHParams, pBytes...)
	serverDHParams = append(serverDHParams, byte(len(gBytes)>>8), byte(len(gBytes)))
	serverDHParams = append(serverDHParams, gBytes...)
	serverDHParams = append(serverDHParams, byte(len(yBytes)>>8), byte(len(yBytes)))
	serverDHParams = append(serverDHParams, yBytes...)

	return ka.auth.signParameters(config, cert, clientHello, hello, serverDHParams)
}

func (ka *dheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg) ([]byte, error) {
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}
	yLen := (int(ckx.ciphertext[0]) << 8) | int(ckx.ciphertext[1])
	if yLen != len(ckx.ciphertext)-2 {
		return nil, errClientKeyExchange
	}
	yTheirs := new(big.Int).SetBytes(ckx.ciphertext[2:])
	ka.yClient = new(big.Int).Set(yTheirs)
	if yTheirs.Sign() <= 0 || yTheirs.Cmp(ka.p) >= 0 {
		return nil, errClientKeyExchange
	}
	return new(big.Int).Exp(yTheirs, ka.xOurs, ka.p).Bytes(), nil
}

func (ka *dheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	// Read dh_p
	k := skx.key
	if len(k) < 2 {
		return errServerKeyExchange
	}
	pLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < pLen {
		return errServerKeyExchange
	}
	ka.p = new(big.Int).SetBytes(k[:pLen])
	k = k[pLen:]

	// Read dh_g
	if len(k) < 2 {
		return errServerKeyExchange
	}
	gLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < gLen {
		return errServerKeyExchange
	}
	ka.g = new(big.Int).SetBytes(k[:gLen])
	k = k[gLen:]

	// Read dh_Ys
	if len(k) < 2 {
		return errServerKeyExchange
	}
	yLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < yLen {
		return errServerKeyExchange
	}
	ka.yTheirs = new(big.Int).SetBytes(k[:yLen])
	ka.yServer = new(big.Int).Set(ka.yTheirs)
	k = k[yLen:]
	if ka.yTheirs.Sign() <= 0 || ka.yTheirs.Cmp(ka.p) >= 0 {
		return errServerKeyExchange
	}

	sig := k
	serverDHParams := skx.key[:len(skx.key)-len(sig)]
	ka.verifyError = ka.auth.verifyParameters(config, clientHello, serverHello, cert, serverDHParams, sig)
	if config.InsecureSkipVerify {
		return nil
	}
	return ka.verifyError
}

func (ka *dheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.p == nil || ka.g == nil || ka.yTheirs == nil {
		return nil, nil, errors.New("missing ServerKeyExchange message")
	}

	var err error
	var yOurs *big.Int
	xOurs := big.NewInt(0)
	var preMasterSecret []byte
	switch config.KexConfig {
	case "0":
		yOurs = big.NewInt(0)
		preMasterSecret = yOurs.Bytes()
	case "1":
		yOurs = big.NewInt(1)
		preMasterSecret = yOurs.Bytes()
	case "pm1":
		yOurs = new(big.Int).Sub(ka.p, big.NewInt(1))
		preMasterSecret = yOurs.Bytes()
	case "g3":
		pm1 := new(big.Int).Sub(ka.p, big.NewInt(1))
		gen := new(big.Int)
		pm1d3, rem := new(big.Int).DivMod(pm1, big.NewInt(3), new(big.Int))
		if rem.Cmp(big.NewInt(0)) == 0 {
			// p-1 is divisible by 3
			done := false
			for !done {
				h, _ := rand.Int(config.rand(), ka.p)
				gen.Exp(h, pm1d3, ka.p)
				if gen.Cmp(big.NewInt(1)) != 0 {
					done = true
				}
			}
		} else {
			err = errors.New("order not divisible by 3")
		}
		yOurs = gen
		preMasterSecret = yOurs.Bytes()
	case "g5":
		pm1 := new(big.Int).Sub(ka.p, big.NewInt(1))
		gen := new(big.Int)
		pm1d5, rem := new(big.Int).DivMod(pm1, big.NewInt(5), new(big.Int))
		if rem.Cmp(big.NewInt(0)) == 0 {
			// p-1 is divisible by 5
			done := false
			for !done {
				h, _ := rand.Int(config.rand(), ka.p)
				gen.Exp(h, pm1d5, ka.p)
				if gen.Cmp(big.NewInt(1)) != 0 {
					done = true
				}
			}
		} else {
			err = errors.New("order not divisible by 5")
		}
		yOurs = gen
		preMasterSecret = yOurs.Bytes()
	case "g7":
		pm1 := new(big.Int).Sub(ka.p, big.NewInt(1))
		gen := new(big.Int)
		pm1d7, rem := new(big.Int).DivMod(pm1, big.NewInt(7), new(big.Int))
		if rem.Cmp(big.NewInt(0)) == 0 {
			// p-1 is divisible by 7
			done := false
			for !done {
				h, _ := rand.Int(config.rand(), ka.p)
				gen.Exp(h, pm1d7, ka.p)
				if gen.Cmp(big.NewInt(1)) != 0 {
					done = true
				}
			}
		} else {
			err = errors.New("order not divisible by 7")
		}
		yOurs = gen
		preMasterSecret = yOurs.Bytes()
	default:
		xOurs, err = rand.Int(config.rand(), ka.p)
		preMasterSecret = new(big.Int).Exp(ka.yTheirs, xOurs, ka.p).Bytes()
		yOurs = new(big.Int).Exp(ka.g, xOurs, ka.p)
	}

	if err != nil {
		return nil, nil, err
	}
	ka.yOurs = yOurs
	ka.xOurs = xOurs
	ka.yClient = new(big.Int).Set(yOurs)
	yBytes := yOurs.Bytes()
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 2+len(yBytes))
	ckx.ciphertext[0] = byte(len(yBytes) >> 8)
	ckx.ciphertext[1] = byte(len(yBytes))
	copy(ckx.ciphertext[2:], yBytes)

	return preMasterSecret, ckx, nil
}
