package strenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

type Entry struct {
	Ciphertext []byte
	IV         [16]byte
}

type Pool struct {
	data      []byte
	offsets   []int
	lengths   []int
	entries   int
	masterKey [32]byte
}

func NewPool(masterKeySeed [32]byte, entries []Entry) *Pool {
	p := &Pool{
		masterKey: DeriveMasterKey(masterKeySeed),
	}
	p.entries = len(entries)

	totalSize := 0
	for _, e := range entries {
		totalSize += 16 + len(e.Ciphertext)
	}

	p.data = make([]byte, 0, totalSize)
	p.offsets = make([]int, len(entries))
	p.lengths = make([]int, len(entries))

	for i, e := range entries {
		p.offsets[i] = len(p.data)
		p.data = append(p.data, e.IV[:]...)
		p.data = append(p.data, e.Ciphertext...)
		p.lengths[i] = 16 + len(e.Ciphertext)
	}

	return p
}

func (p *Pool) StringCount() int {
	return p.entries
}

func (p *Pool) deriveSubkey(iv [16]byte) [32]byte {
	mac := hmac.New(sha256.New, p.masterKey[:])
	mac.Write(iv[:])
	var subkey [32]byte
	copy(subkey[:], mac.Sum(nil))
	return subkey
}

func (p *Pool) decryptAt(index int) ([]byte, error) {
	if index < 0 || index >= p.entries {
		return nil, fmt.Errorf("strenc: index %d out of range [0, %d)", index, p.entries)
	}

	start := p.offsets[index]
	raw := p.data[start : start+p.lengths[index]]

	var iv [16]byte
	copy(iv[:], raw[:16])
	ct := raw[16:]

	subkey := p.deriveSubkey(iv)
	block, err := aes.NewCipher(subkey[:])
	if err != nil {
		return nil, fmt.Errorf("strenc: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("strenc: cipher.NewGCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ct) < nonceSize {
		return nil, fmt.Errorf("strenc: ciphertext too short")
	}

	nonce := ct[:nonceSize]
	ciphertext := ct[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("strenc: gcm.Open: %w", err)
	}

	return plaintext, nil
}

func (p *Pool) GetString(index int) string {
	pt, err := p.decryptAt(index)
	if err != nil {
		return ""
	}
	return string(pt)
}

func (p *Pool) GetStringZero(index int, fn func(string)) {
	pt, err := p.decryptAt(index)
	if err != nil {
		fn("")
		return
	}

	buf := make([]byte, len(pt))
	copy(buf, pt)
	s := string(buf)

	for i := range pt {
		pt[i] = 0
	}

	fn(s)

	for i := range buf {
		buf[i] = 0
	}
}

func EncryptEntry(plaintext string, key [32]byte, iv [16]byte) Entry {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(fmt.Sprintf("strenc: aes.NewCipher: %v", err))
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("strenc: cipher.NewGCM: %v", err))
	}

	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	copy(nonce, iv[:nonceSize])

	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return Entry{
		Ciphertext: ct,
		IV:         iv,
	}
}
