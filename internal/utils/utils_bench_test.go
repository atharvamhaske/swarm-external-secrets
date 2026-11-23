package utils

import (
	"encoding/base64"
	"testing"
)

func BenchmarkDecodeBase64Secret(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{name: "32B", size: 32},
		{name: "4KiB", size: 4 * 1024},
		{name: "384KiB", size: 384 * 1024},
	} {
		b.Run(tc.name, func(b *testing.B) {
			encoded := []byte(base64.StdEncoding.EncodeToString(make([]byte, tc.size)))
			b.SetBytes(int64(len(encoded)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := DecodeBase64Secret(encoded, "benchmark-secret", "value"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
