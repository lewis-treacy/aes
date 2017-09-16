// Advanced Encryption Standard implementation
package aes

func rotw(w uint32) uint32 {
	return (w<<8) | (w>>24)
}

func sub(b byte) byte {
	return sbox[uint8(b)]
}

