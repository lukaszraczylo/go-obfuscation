package syscallobf

// ObfuscatedCall wraps a syscall with obfuscated number
type ObfuscatedCall struct {
	encodedNum [4]byte
	key        [4]byte
}

func (o *ObfuscatedCall) Num() uintptr {
	return uintptr(o.encodedNum[0]^o.key[0]) |
		uintptr(o.encodedNum[1]^o.key[1])<<8 |
		uintptr(o.encodedNum[2]^o.key[2])<<16 |
		uintptr(o.encodedNum[3]^o.key[3])<<24
}

func encode(num uintptr, key [4]byte) ObfuscatedCall {
	return ObfuscatedCall{
		encodedNum: [4]byte{
			byte(num&0xff) ^ key[0],
			byte((num>>8)&0xff) ^ key[1],
			byte((num>>16)&0xff) ^ key[2],
			byte((num>>24)&0xff) ^ key[3],
		},
		key: key,
	}
}
