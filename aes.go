// Advanced Encryption Standard implementation
package aes

func expandKey(key []byte) []byte {
	var exKey = make([]byte, 256)
	return exKey
}

// Rotate 32 bit word left by 1 byte
func rotw(w uint32) uint32 {
	return (w<<8) | (w>>24)
}

// Gets S-Box substitution value for a byte
func sub(b byte) byte {
	return sbox[uint8(b)]
}

// Gets round constant
// Pre: b > 0
func rcon(b uint8) uint32 {
	return uint32(rcon_const[b - 1]) << 24
}
