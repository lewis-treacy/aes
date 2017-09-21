// Advanced Encryption Standard implementation.
package aes

type key struct {
	key    []byte
	xkey   []byte
	rounds int
}

// Rotate word left 1 byte
func rotw(w []byte) {
	temp := w[0]
	w[0] = w[1]
	w[1] = w[2]
	w[2] = w[3]
	w[3] = temp
}

// Returns substitute byte according to Rijndael's S-box
func getSboxSub(b byte) byte {
	return sbox[b]
}

// Returns substitute byte according to Rijndael's inverse S-box
func getInvSboxSub(b byte) byte {
	return rsbox[b]
}

// Substitutes each byte according to Rijndael's S-box
func subBytes(s []byte) {
	for i, v := range s {
		s[i] = getSboxSub(v)
	}
}

// Substitutes each byte according to Rijndael's inverse S-box
func invSubBytes(s []byte) {
	for i, v := range s {
		s[i] = getInvSboxSub(v)
	}
}

// Returns round constant
// Pre: 0 < round <= 10
func getRcon(round int) byte {
	return rcon_const[round-1]
}

// Expands key according to the Rijndael key schedule
// Pre: key is 16, 24 or 32 bytes in length
func expandKey(key []byte) []byte {
	nk := len(key) / 4
	xKey := make([]byte, 16*(rounds[len(key)]+1))

	// Beginning of the expanded key is the same
	i := 0
	for ; i < nk; i++ {
		xKey[(4*i)+0] = key[(4*i)+0]
		xKey[(4*i)+1] = key[(4*i)+1]
		xKey[(4*i)+2] = key[(4*i)+2]
		xKey[(4*i)+3] = key[(4*i)+3]
	}

	temp := make([]byte, 4)
	for ; i < len(xKey)/4; i++ {
		temp[0] = xKey[4*(i-1)+0]
		temp[1] = xKey[4*(i-1)+1]
		temp[2] = xKey[4*(i-1)+2]
		temp[3] = xKey[4*(i-1)+3]

		if i%nk == 0 {
			// Rotate word
			rotw(temp)
			// Sub word
			subBytes(temp)
			// Rcon
			temp[0] = temp[0] ^ getRcon(i/nk)
		} else if nk > 6 && i%nk == 4 {
			// Sub word
			subBytes(temp)
		}
		xKey[(4*i)+0] = xKey[4*(i-nk)+0] ^ temp[0]
		xKey[(4*i)+1] = xKey[4*(i-nk)+1] ^ temp[1]
		xKey[(4*i)+2] = xKey[4*(i-nk)+2] ^ temp[2]
		xKey[(4*i)+3] = xKey[4*(i-nk)+3] ^ temp[3]
	}
	return xKey
}

// Adds (xor) state to round key
func addRoundKey(s []byte, w []byte) {
	for i, v := range s {
		s[i] = v ^ w[i]
	}
}

// Shifts rows to the right, by one more byte for each row
func shiftRows(s []byte) {
	t := make([]byte, 4)
	for i := 0; i < 4; i++ {
		t[0] = s[5*i]
		t[1] = s[((5*i)+4)%16]
		t[2] = s[((5*i)+8)%16]
		t[3] = s[((5*i)+12)%16]

		s[i] = t[0]
		s[4+i] = t[1]
		s[8+i] = t[2]
		s[12+i] = t[3]
	}
}

// Galois Field (2^8) Multiplication of two Bytes
func gfMul(a, b byte) byte {
	var prod byte = 0
	var h byte
	for i := 0; i < 8; i++ {
		if (b & 0x01) != 0 {
			prod ^= a
		}
		h = a >> 7
		a <<= 1
		if h != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return prod
}

// Mix columns as coefficients of a polynomial over Rijndael's Galois field
func mixColumns(s []byte) {
	a := make([]byte, 4)
	for i := 0; i < 4; i++ {
		a[0] = s[(4*i)+0]
		a[1] = s[(4*i)+1]
		a[2] = s[(4*i)+2]
		a[3] = s[(4*i)+3]

		s[(4*i)+0] = gfMul(0x02, a[0]) ^ a[3] ^ a[2] ^ gfMul(0x03, a[1]) /* 2*a0 + a3 + a2 + 3*a1 */
		s[(4*i)+1] = gfMul(0x02, a[1]) ^ a[0] ^ a[3] ^ gfMul(0x03, a[2]) /* 2*a1 + a0 + a3 + 3*a2 */
		s[(4*i)+2] = gfMul(0x02, a[2]) ^ a[1] ^ a[0] ^ gfMul(0x03, a[3]) /* 2*a2 + a1 + a0 + 3*a3 */
		s[(4*i)+3] = gfMul(0x02, a[3]) ^ a[2] ^ a[1] ^ gfMul(0x03, a[0]) /* 2*a3 + a2 + a1 + 3*a0 */
	}
}

// Encrypts one 16 byte block in place in memory
func encryptBlock(s []byte, k *key) {
	// Add round key
	addRoundKey(s, k.xkey)
	for i := 1; i < k.rounds; i++ {
		// Sub bytes
		subBytes(s)
		// Shift rows, wrong
		shiftRows(s)
		// Mix columns
		mixColumns(s)
		// Add round key
		addRoundKey(s, k.xkey[i*16:])
	}

	// Sub bytes
	subBytes(s)
	// Shift rows
	shiftRows(s)
	// Add round key
	addRoundKey(s, k.xkey[len(k.xkey)-16:])
}
