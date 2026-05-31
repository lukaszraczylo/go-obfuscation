package pageman

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

var (
	ErrAlreadyLocked   = errors.New("pageman: buffer already locked")
	ErrAlreadyUnlocked = errors.New("pageman: buffer already unlocked")
	ErrClosed          = errors.New("pageman: buffer closed")
)

type SecureBuffer struct {
	mu         sync.Mutex
	data       []byte
	encrypted  []byte
	key        [32]byte
	locked     bool
	closed     bool
	lastAccess time.Time
	autoLock   time.Duration
}

func NewSecureBuffer(initialData []byte, autoLock time.Duration) *SecureBuffer {
	sb := &SecureBuffer{
		data:       make([]byte, len(initialData)),
		autoLock:   autoLock,
		lastAccess: time.Now(),
	}
	copy(sb.data, initialData)

	if _, err := rand.Read(sb.key[:]); err != nil {
		panic("pageman: failed to generate key: " + err.Error())
	}

	sb.encryptInPlace()
	sb.locked = true

	for i := range initialData {
		initialData[i] = 0
	}

	return sb
}

func (sb *SecureBuffer) Lock() error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return ErrClosed
	}
	if sb.locked {
		return ErrAlreadyLocked
	}

	sb.encryptInPlace()
	sb.locked = true
	return nil
}

func (sb *SecureBuffer) Unlock() error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return ErrClosed
	}
	if !sb.locked {
		return ErrAlreadyUnlocked
	}

	sb.decryptInPlace()
	sb.locked = false
	sb.lastAccess = time.Now()
	return nil
}

func (sb *SecureBuffer) Access(fn func([]byte)) error {
	sb.mu.Lock()

	if sb.closed {
		sb.mu.Unlock()
		return ErrClosed
	}

	wasLocked := sb.locked
	if wasLocked {
		sb.decryptInPlace()
		sb.locked = false
	}

	sb.lastAccess = time.Now()

	fn(sb.data)

	if wasLocked {
		sb.encryptInPlace()
		sb.locked = true
	}

	sb.mu.Unlock()
	return nil
}

func (sb *SecureBuffer) Close() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return
	}

	sb.zeroSlice(sb.data)
	sb.zeroSlice(sb.encrypted)
	sb.zeroKey()
	sb.data = nil
	sb.encrypted = nil
	sb.locked = true
	sb.closed = true
}

func (sb *SecureBuffer) IsLocked() bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.locked
}

func (sb *SecureBuffer) IsClosed() bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.closed
}

func (sb *SecureBuffer) LastAccess() time.Time {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.lastAccess
}

func (sb *SecureBuffer) AutoLockDuration() time.Duration {
	return sb.autoLock
}

func (sb *SecureBuffer) forceLock() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed || sb.locked {
		return
	}

	sb.encryptInPlace()
	sb.locked = true
}

func (sb *SecureBuffer) encryptInPlace() {
	if len(sb.data) == 0 {
		return
	}

	sb.encrypted = make([]byte, len(sb.data))
	for i, b := range sb.data {
		sb.encrypted[i] = b ^ sb.key[i%32]
	}

	for i := 0; i < 32; i++ {
		sb.key[i] = rotateKey(sb.key[i], i)
	}

	sb.zeroSlice(sb.data)
	sb.data = nil
}

func (sb *SecureBuffer) decryptInPlace() {
	if len(sb.encrypted) == 0 {
		return
	}

	for i := 0; i < 32; i++ {
		sb.key[i] = unrotateKey(sb.key[i], i)
	}

	sb.data = make([]byte, len(sb.encrypted))
	for i, b := range sb.encrypted {
		sb.data[i] = b ^ sb.key[i%32]
	}

	sb.zeroSlice(sb.encrypted)
	sb.encrypted = nil
}

func (sb *SecureBuffer) zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (sb *SecureBuffer) zeroKey() {
	for i := range sb.key {
		sb.key[i] = 0
	}
}

func rotateKey(b byte, pos int) byte {
	shift := uint((pos*3 + 7) % 8)
	return b<<shift | b>>(8-shift)
}

func unrotateKey(b byte, pos int) byte {
	shift := uint((pos*3 + 7) % 8)
	return b>>shift | b<<(8-shift)
}
