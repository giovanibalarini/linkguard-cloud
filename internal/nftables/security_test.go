package nftables

import "testing"

func TestValidMarkRejectsInjection(t *testing.T) {
	ok := []string{"0x12c", "0x1", "300", "0xABCDEF"}
	for _, m := range ok {
		if !ValidMark(m) {
			t.Errorf("mark %q should be valid", m)
		}
	}
	// nft-injection payloads must be rejected.
	bad := []string{
		"0x1 }; flush ruleset; add element inet linkguard host_wan { 1.1.1.1 : 0x1",
		"0x1; drop",
		"300 }",
		"0xzz",
		"", "0x", "; flush ruleset",
	}
	for _, m := range bad {
		if ValidMark(m) {
			t.Errorf("mark %q must be rejected (injection)", m)
		}
	}
}
