package aes

import "testing"

func Test_rotr(t *testing.T) {
	for _, c := range []struct {
		in uint32
		want uint32
	}{
		{0x01020304, 0x02030401},
		{0xFFFEFDFC, 0xFEFDFCFF},
	}{
		got := rotw(c.in)
		if got != c.want {
			t.Errorf("rotw(0x%X) == 0x%X, want 0x%X", c.in, got, c.want)
		}
	}
}

func Test_sub(t *testing.T) {
	for _, c := range []struct {
		in byte
		want byte
	}{
		{0x53, 0xED},
		{0x00, 0x63},
		{0xFF, 0x16},
	}{
		got := sub(c.in)
		if got != c.want {
			t.Errorf("sub(0x%X) == 0x%X, want 0x%X", c.in, got, c.want)
		}
	}
}
