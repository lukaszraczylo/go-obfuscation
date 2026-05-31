package strenc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"runtime"
)

const buildSeed = 0xDEAD_BEEF_CAFE_BABE

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

func DeriveFromBinary() [32]byte {
	exePath, err := os.Executable()
	if err != nil {
		exePath = "unknown"
	}

	mac := hmac.New(sha256.New, []byte("strenc.binary.seed"))
	mac.Write([]byte(exePath))

	var seedBuf [8]byte
	binary.LittleEndian.PutUint64(seedBuf[:], buildSeed)
	mac.Write(seedBuf[:])

	mac.Write([]byte(runtime.GOOS))
	mac.Write([]byte(runtime.GOARCH))

	var seed [32]byte
	copy(seed[:], mac.Sum(nil))

	return DeriveMasterKey(seed)
}
