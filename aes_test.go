package aes

import (
	"testing"
	"errors"
	"fmt"
)

func Test_expandKey(t *testing.T) {
	for _, c := range []struct {
		in []byte
		want []uint32
	}{
		{[]byte{
			0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
			0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
		},
		[]uint32{
			0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C,
			0xA0FAFE17, 0x88542CB1, 0x23A33939, 0x2A6C7605,
			0xF2C295F2, 0x7A96B943, 0x5935807A, 0x7359F67F,
			0x3D80477D, 0x4716FE3E, 0x1E237E44, 0x6D7A883B,
			0xEF44A541, 0xA8525B7F, 0xB671253B, 0xDB0BAD00,
			0xD4D1C6F8, 0x7C839D87, 0xCAF2B8BC, 0x11F915BC,
			0x6D88A37A, 0x110B3EFD, 0xDBF98641, 0xCA0093FD,
			0x4E54F70E, 0x5F5FC9F3, 0x84A64FB2, 0x4EA6DC4F,
			0xEAD27321, 0xB58DBAD2, 0x312BF560, 0x7F8D292F,
			0xAC7766F3, 0x19FADC21, 0x28D12941, 0x575C006E,
			0xD014F9A8, 0xC9EE2589, 0xE13F0CC8, 0xB6630CA6,
		}},

		{[]byte{
			0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
			0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
			0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B,
		},
		[]uint32{
			0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5,
			0x62F8EAD2, 0x522C6B7B, 0xFE0C91F7, 0x2402F5A5,
			0xEC12068E, 0x6C827F6B, 0x0E7A95B9, 0x5C56FEC2,
			0x4DB7B4BD, 0x69B54118, 0x85A74796, 0xE92538FD,
			0xE75FAD44, 0xBB095386, 0x485AF057, 0x21EFB14F,
			0xA448F6D9, 0x4D6DCE24, 0xAA326360, 0x113B30E6,
			0xA25E7ED5, 0x83B1CF9A, 0x27F93943, 0x6A94F767,
			0xC0A69407, 0xD19DA4E1, 0xEC1786EB, 0x6FA64971,
			0x485F7032, 0x22CB8755, 0xE26D1352, 0x33F0B7B3,
			0x40BEEB28, 0x2F18A259, 0x6747D26B, 0x458C553E,
			0xA7E1466C, 0x9411F1DF, 0x821F750A, 0xAD07D753,
			0xCA400538, 0x8FCC5006, 0x282D166A, 0xBC3CE7B5,
			0xE98BA06F, 0x448C773C, 0x8ECC7204, 0x01002202,
		}},

		{[]byte{
			0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
			0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
			0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
			0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4,
		},
		[]uint32{
			0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
			0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4,
			0x9BA35411, 0x8E6925AF, 0xA51A8B5F, 0x2067FCDE,
			0xA8B09C1A, 0x93D194CD, 0xBE49846E, 0xB75D5B9A,
			0xD59AECB8, 0x5BF3C917, 0xFEE94248, 0xDE8EBE96,
			0xB5A9328A, 0x2678A647, 0x98312229, 0x2F6C79B3,
			0x812C81AD, 0xDADF48BA, 0x24360AF2, 0xFAB8B464,
			0x98C5BFC9, 0xBEBD198E, 0x268C3BA7, 0x09E04214,
			0x68007BAC, 0xB2DF3316, 0x96E939E4, 0x6C518D80,
			0xC814E204, 0x76A9FB8A, 0x5025C02D, 0x59C58239,
			0xDE136967, 0x6CCC5A71, 0xFA256395, 0x9674EE15,
			0x5886CA5D, 0x2E2F31D7, 0x7E0AF1FA, 0x27CF73C3,
			0x749C47AB, 0x18501DDA, 0xE2757E4F, 0x7401905A,
			0xCAFAAAE3, 0xE4D59B34, 0x9ADF6ACE, 0xBD10190D,
			0xFE4890D1, 0xE6188D0B, 0x046DF344, 0x706C631E,
		}},
	}{
		got := expandKey(c.in)
		if ok, err := compareWords(got, c.want); !ok {
			t.Errorf("expandKey(%X) failed: %q", c.in, err.Error())
		}
	}
}

func compareWords(a, b []uint32) (bool, error) {
	if len(a) != len(b) {
		return false, errors.New("lengths differ")
	}
	for i, v := range a {
		if v != b[i] {
			return false, errors.New(fmt.Sprintf("a[%d] = %X, b[%d] = %X", i, v, i, b[i]))
		}
	}
	return true, nil
}