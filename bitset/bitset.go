// Package bitset provides a dynamic, allocation-frugal bit array backed by
// []uint64. It is the storage primitive behind BitGate permission sets.
//
// A Bitset is not safe for concurrent use; callers (the engine) guard it.
package bitset

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

const wordBits = 64

// Bitset is a growable set of bit indices.
type Bitset struct {
	words []uint64
}

// New returns an empty Bitset.
func New() *Bitset { return &Bitset{} }

// Set turns on bit i, growing the backing storage as needed.
func (b *Bitset) Set(i uint) {
	w := i / wordBits
	b.grow(int(w) + 1)
	b.words[w] |= 1 << (i % wordBits)
}

// Clear turns off bit i. Indices beyond the current storage are already unset.
func (b *Bitset) Clear(i uint) {
	w := i / wordBits
	if int(w) < len(b.words) {
		b.words[w] &^= 1 << (i % wordBits)
	}
}

// Test reports whether bit i is set. O(1). Out-of-range indices read as false.
func (b *Bitset) Test(i uint) bool {
	w := i / wordBits
	if int(w) >= len(b.words) {
		return false
	}
	return b.words[w]&(1<<(i%wordBits)) != 0
}

// Or sets b = b | other.
func (b *Bitset) Or(other *Bitset) {
	if len(other.words) > len(b.words) {
		b.grow(len(other.words))
	}
	for i, w := range other.words {
		b.words[i] |= w
	}
}

// Count returns the number of set bits.
func (b *Bitset) Count() int {
	n := 0
	for _, w := range b.words {
		n += bits.OnesCount64(w)
	}
	return n
}

// Clone returns an independent copy of the bitset.
func (b *Bitset) Clone() *Bitset {
	next := make([]uint64, len(b.words))
	copy(next, b.words)
	return &Bitset{words: next}
}

// MarshalBinary encodes the set as little-endian uint64 words with trailing
// zero words trimmed, so the encoding is canonical and compact. It implements
// encoding.BinaryMarshaler.
func (b *Bitset) MarshalBinary() ([]byte, error) {
	n := len(b.words)
	for n > 0 && b.words[n-1] == 0 {
		n--
	}
	out := make([]byte, n*8)
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], b.words[i])
	}
	return out, nil
}

// UnmarshalBinary restores a set produced by MarshalBinary. It implements
// encoding.BinaryUnmarshaler.
func (b *Bitset) UnmarshalBinary(data []byte) error {
	if len(data)%8 != 0 {
		return errors.New("bitset: invalid encoded length")
	}
	n := len(data) / 8
	words := make([]uint64, n)
	for i := 0; i < n; i++ {
		words[i] = binary.LittleEndian.Uint64(data[i*8:])
	}
	b.words = words
	return nil
}

func (b *Bitset) grow(n int) {
	if n <= len(b.words) {
		return
	}
	next := make([]uint64, n)
	copy(next, b.words)
	b.words = next
}
