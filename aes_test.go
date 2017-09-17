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
			t.Errorf("rotw(0x%08X) == 0x%08X, want 0x%08X", c.in, got, c.want)
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
			t.Errorf("sub(0x%02X) == 0x%02X, want 0x%02X", c.in, got, c.want)
		}
	}
}

func Test_rcon(t *testing.T) {
	for _, c := range []struct {
		in uint8
		want uint32
	}{
		{0x01, 0x01000000},
		{0x0E, 0x4D000000},
		{0x0F, 0x9A000000},
	}{
		got := rcon(c.in)
		if got != c.want {
			t.Errorf("rcon(0x%02X) == 0x%08X, want 0x%08X", c.in, got, c.want)
		}
	}
}
