package termsafe

import "testing"

func TestObeyed(t *testing.T) {
	for _, r := range []rune{0x00, 0x07, 0x1b, '\n', '\t', '\r', 0x7f, 0x80, 0x9b, 0x9f,
		0x202a, 0x202e, 0x2066, 0x2069, 0x200e, 0x200f, 0x061c} {
		if !Obeyed(r) {
			t.Errorf("U+%04X is obeyed by a terminal and was reported as drawn", r)
		}
	}
	for _, r := range []rune{' ', 'a', '~', 0xa0, 'é', '日', 0x2029, 0x202f, 0x2065, 0x206a, 0x1f600} {
		if Obeyed(r) {
			t.Errorf("U+%04X is an ordinary character and was reported as obeyed", r)
		}
	}
}
