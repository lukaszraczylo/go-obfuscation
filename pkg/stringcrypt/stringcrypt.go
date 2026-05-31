package stringcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

type EncryptedString struct {
	ciphertext []byte
	key        []byte
}

func Encrypt(plaintext string) EncryptedString {
	data := []byte(plaintext)
	key := make([]byte, len(data))
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("stringcrypt: rand.Read failed: %v", err))
	}

	ciphertext := make([]byte, len(data))
	for i := range data {
		ciphertext[i] = data[i] ^ key[i]
	}

	return EncryptedString{ciphertext: ciphertext, key: key}
}

func (e EncryptedString) Decrypt() string {
	plaintext := make([]byte, len(e.ciphertext))
	for i := range e.ciphertext {
		plaintext[i] = e.ciphertext[i] ^ e.key[i]
	}
	return string(plaintext)
}

func (e EncryptedString) CiphertextB64() string {
	return base64.StdEncoding.EncodeToString(e.ciphertext)
}

func (e EncryptedString) KeyB64() string {
	return base64.StdEncoding.EncodeToString(e.key)
}

func GenerateRuntimeDecryptCall(ctB64, keyB64 string) string {
	return fmt.Sprintf(
		`(func() string {
			_ct, _ := base64.StdEncoding.DecodeString(%q)
			_ky, _ := base64.StdEncoding.DecodeString(%q)
			_pt := make([]byte, len(_ct))
			for _i := range _ct {
				_pt[_i] = _ct[_i] ^ _ky[_i]
			}
			return string(_pt)
		})()`, ctB64, keyB64)
}

func RandomIdent(prefix string, length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(fmt.Sprintf("stringcrypt: rand.Int failed: %v", err))
		}
		b[i] = charset[n.Int64()]
	}
	return prefix + string(b)
}
