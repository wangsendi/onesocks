package domain

import (
	"encoding/json"
	"testing"
)

func TestNodeIDIncludesSubscriptionIDNodeNameAndSeparator(t *testing.T) {
	for _, tc := range []struct {
		subscriptionID, name, want string
	}{
		{"s_a", "香港01", "n_c79598ae996b0511d3a0c07d25dfee2c"},
		{"ab", "c", "n_cf1aa1426d75f0e4c1a49da3b28808ef"},
		{"a", "bc", "n_a5f5d1ebd362d6639389a7e1fede534d"},
	} {
		if got := NodeID(tc.subscriptionID, tc.name); got != tc.want {
			t.Errorf("NodeID(%q, %q) = %q, want %q", tc.subscriptionID, tc.name, got, tc.want)
		}
	}
}

func TestEqualOutboundIgnoresObjectOrderingWithoutRoundingNumbers(t *testing.T) {
	for _, test := range []struct {
		left, right string
		equal       bool
	}{
		{`{"type":"socks","tls":{"enabled":true,"server_name":"example.test"}}`, ` {"tls": {"server_name":"example.test", "enabled":true}, "type":"socks"} `, true},
		{`{"port":9007199254740992}`, `{"port":9007199254740993}`, false},
		{`{"ports":[1,2]}`, `{"ports":[2,1]}`, false},
		{`{"tls":false}`, `{"tls":true}`, false},
		{`{"type":"socks"}`, `not JSON`, false},
	} {
		if got := EqualOutbound(json.RawMessage(test.left), json.RawMessage(test.right)); got != test.equal {
			t.Errorf("EqualOutbound(%s, %s)=%v, want %v", test.left, test.right, got, test.equal)
		}
	}
}
