package noise

import (
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"hash"
)

const (
	NoisePublicKeySize  = 32
	NoisePrivateKeySize = 32
	NoiseConstruction   = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
	NoiseIdentifier     = "DePlus v1 215572162@qq.com"

	FLG_HSH byte = 0x10 // handshaking
	FLG_HBT byte = 0x08 // heartbeat
	FLG_FIN byte = 0x04 // finish
	FLG_ACK byte = 0x02 // acknowledge
	FLG_DAT byte = 0x00 // transport data

	STAT_INIT      int32 = iota // initing
	STAT_HANDSHAKE              // handeshaking
	STAT_WORKING                // working

	HDR_LEN        int = 9
	UDP_BUFFER     int = 65535
	PAYLOAD_BUFFER int = UDP_BUFFER - HDR_LEN
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoiseSymmetricKey [chacha20poly1305.KeySize]byte
)

func newPrivateKey() NoisePrivateKey {
	var sk NoisePrivateKey
	_, err := rand.Read(sk[:])
	if err != nil {
		fmt.Println("私钥生成失败:", err)
	}
	return sk
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func NewKeyPair() (NoisePrivateKey, NoisePublicKey) {
	sk := newPrivateKey()
	pk := sk.publicKey()
	return sk, pk
}

func (sk *NoisePrivateKey) SharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)
	return ss
}

func MixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func MixKey(dst *[blake2s.Size]byte, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func HMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func (TSend *NoiseSymmetricKey) Encrypt(orig []byte) []byte {
	return AesEncrypt(orig, TSend[:])
}

func (TRecv *NoiseSymmetricKey) Decrypt(crypted []byte) []byte {
	return AesDecrypt(crypted, TRecv[:])
}
