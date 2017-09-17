// Advanced Encryption Standard implementation.
package aes

type key struct {
	key []byte
	xkey []uint32
	rounds int
}

func encryptBlock(b []byte, k *key) []byte {
	s := make([]uint32, 4)
	s[0] = uint32(b[0]) << 24 | uint32(b[1]) << 16 | uint32(b[2]) << 8 | uint32(b[3])
	s[1] = uint32(b[4]) << 24 | uint32(b[5]) << 16 | uint32(b[6]) << 8 | uint32(b[7])
	s[2] = uint32(b[8]) << 24 | uint32(b[9]) << 16 | uint32(b[10]) << 8 | uint32(b[11])
	s[2] = uint32(b[12]) << 24 | uint32(b[13]) << 16 | uint32(b[14]) << 8 | uint32(b[15])

	s = addRoundKey(s, k.xkey)
	for i := 1; i < k.rounds; i++{
		// Sub bytes
		s[0] = subw(s[0])
		s[1] = subw(s[1])
		s[2] = subw(s[2])
		s[3] = subw(s[3])
		// Shift rows
		s[1] = (s[1]<<8) | (s[1]>>24)
		s[2] = (s[2]<<16) | (s[2]>>16)
		s[3] = (s[3]<<24) | (s[3]>>8)
		//TODO: Mix columns
		s = addRoundKey(s, k.xkey[i*4:])
	}

	return []byte{0}
}

func addRoundKey(s []uint32, w []uint32) []uint32 {
	s[0] ^= w[0]
	s[1] ^= w[1]
	s[2] ^= w[2]
	s[3] ^= w[3]
	return s
}

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
