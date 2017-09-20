// Advanced Encryption Standard implementation.
package aes

type key struct {
	key []byte
	xkey []byte
	rounds int
}

// Rotate word left 1 byte
func rotw(w []byte) []byte {
	temp := w[0]
	w[0] = w[1]
	w[1] = w[2]
	w[2] = w[3]
	w[3] = temp
	return w
}

// Returns substitute byte according to Rijndael's S-box
func getSboxSub(b byte) byte {
	return sbox[b]
}

// Returns round constant
// Pre: 0 < round <= 10
func getRcon(round int) byte {
	return rcon_const[round - 1]
}

// Expands key according to the Rijndael key schedule
// Pre: key is 16, 24 or 32 bytes in length
func expandKey(key []byte) []byte {
	nk := len(key) / 4
	xKey := make([]byte, 16*(rounds[len(key)] + 1))

	// Begining of the expanded key is the same
	i := 0
	for ; i < nk; i++ {
		xKey[(4*i)+0] = key[(4*i)+0]
		xKey[(4*i)+1] = key[(4*i)+1]
		xKey[(4*i)+2] = key[(4*i)+2]
		xKey[(4*i)+3] = key[(4*i)+3]
	}

	temp := make([]byte, 4)
	for ; i < len(xKey)/4; i++ {
		temp[0] = xKey[4*(i-1) + 0]
		temp[1] = xKey[4*(i-1) + 1]
		temp[2] = xKey[4*(i-1) + 2]
		temp[3] = xKey[4*(i-1) + 3]

		if i % nk == 0 {
			// Rotate word
			temp = rotw(temp)
			// Sub word
			temp = subBytes(temp)
			// Rcon
			temp[0] = temp[0] ^ getRcon(i/nk)
		} else if nk > 6 && i % nk == 4 {
			// Sub word
			temp = subBytes(temp)
		}
		xKey[(4*i) + 0] = xKey[4*(i-nk) + 0] ^ temp[0]
		xKey[(4*i) + 1] = xKey[4*(i-nk) + 1] ^ temp[1]
		xKey[(4*i) + 2] = xKey[4*(i-nk) + 2] ^ temp[2]
		xKey[(4*i) + 3] = xKey[4*(i-nk) + 3] ^ temp[3]
	}
	return xKey
}

// Adds (xor) state to round key
func addRoundKey(s []byte, w []byte) []byte {
	t := make([]byte, 16)
	for i, v := range s {
		t[i] = v ^ w[i]
	}
	return t
}

// Returns state with each byte substituted according to Rijndael's S-box
func subBytes(s []byte) []byte {
	t := make([]byte, len(s))
	for i, v := range s {
		t[i] = getSboxSub(v)
	}
	return t
}

// Shifts rows to the right, by one more byte for each row
func shiftRows(s []byte) []byte {
	t := make([]byte, 16)
	for i := 0; i < 4; i++ {
		t[i] = s[5*i]
		t[4+i] = s[(4+(5*i)) % 16]
		t[8+i] = s[(8+(5*i)) % 16]
		t[12+i] = s[(12+(5*i)) % 16]
	}
	return t
}

func mixColumns(s []byte) []byte {
	t := make([]byte, 4)
	temp := make([]byte, 16)

	for i := 0; i < 4; i++ {
		t[0] = gf_mul2[s[(4*i) + 0]] ^ s[(4*i) + 3] ^ s[(4*i) + 2] ^ gf_mul3[s[(4*i) + 1]] // 2*a0 + a3 + a2 + 3*a1
		t[1] = gf_mul2[s[(4*i) + 1]] ^ s[(4*i) + 0] ^ s[(4*i) + 3] ^ gf_mul3[s[(4*i) + 2]] // 2*a1 + a0 + a3 + 3*a2
		t[2] = gf_mul2[s[(4*i) + 2]] ^ s[(4*i) + 1] ^ s[(4*i) + 0] ^ gf_mul3[s[(4*i) + 3]] // 2*a2 + a1 + a0 + 3*a3
		t[3] = gf_mul2[s[(4*i) + 3]] ^ s[(4*i) + 2] ^ s[(4*i) + 1] ^ gf_mul3[s[(4*i) + 0]] // 2*a3 + a2 + a1 + 3*a0
		temp[(4*i) + 0] = t[0]
		temp[(4*i) + 1] = t[1]
		temp[(4*i) + 2] = t[2]
		temp[(4*i) + 3] = t[3]
	}
	return temp
}

func encryptBlock(b []byte, k *key) []byte {
	// Add round key
	s := addRoundKey(b, k.xkey)
	for i := 1; i < k.rounds; i++{
		// Sub bytes
		s = subBytes(s)
		// Shift rows, wrong
		s = shiftRows(s)
		// Mix columns
		s = mixColumns(s)
		// Add round key
		s = addRoundKey(s, k.xkey[i*16:])
	}

	// Sub bytes
	s = subBytes(s)
	// Shift rows
	s = shiftRows(s)
	// Add round key
	s = addRoundKey(s, k.xkey[len(k.xkey)-16:])
	return s
}
