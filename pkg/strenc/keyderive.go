package strenc

import (
	"crypto/hmac"
	"crypto/sha256"
)

func DeriveMasterKey(seed [32]byte) [32]byte {
	var out [32]byte

	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte("strenc.masterkey.v1"))
	copy(out[:16], mac.Sum(nil))

	mac.Reset()
	mac.Write(seed[:])
	mac.Write([]byte("strenc.masterkey.v2"))
	copy(out[16:], mac.Sum(nil))

	return out
}
