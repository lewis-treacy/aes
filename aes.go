// Advanced Encryption Standard implementation.
package aes

// Expands key according to the Rijndael key schedule.
// Pre: key is 16, 24 or 32 bytes in length
func expandKey(key []byte) []uint32 {
	nk := len(key) / 4
	w := make([]uint32, 4*(rounds[len(key)] + 1))
	// Begining of the expanded key is the same
	for i := 0; i < nk; i++ {
		w[i] = uint32(key[4*i])<<24 | uint32(key[4*i+1])<<16 | uint32(key[4*i+2])<<8 | uint32(key[4*i+3])
	}

	for j := nk; j < len(w); j++ {
		a := w[j-1]
		if j % nk == 0 {
			a = subw(rotw(a)) ^ rcon(j/nk)
		} else if nk == 8 && j % nk == 4 {
			a = subw(a)
		}
		w[j] = w[j-nk] ^ a
	}

	return w
}

// Rotate word left 1 byte.
func rotw(w uint32) uint32 {
	return (w<<8) | (w>>24)
}

// Substitutes each byte of word w according to Rijndael's S-box.
func subw(w uint32) uint32 {
	return uint32(sbox[w>>24])<<24 | uint32(sbox[(w>>16)&0xFF])<<16 | uint32(sbox[(w>>8)&0xFF])<<8 | uint32(sbox[w&0xFF])
}

// Gets round constant.
// Pre: round > 0
func rcon(round int) uint32 {
	return uint32(rcon_const[round - 1]) << 24
}
