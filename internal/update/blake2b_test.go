package update

import (
	"bufio"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Vectors: testdata/blake2b_vectors.txt, from Python's hashlib.blake2b(digest_size=64),
// over bytes(i % 251 for i in range(n)), including the 128-byte block boundaries.
func TestBlake2b512MatchesHashlib(t *testing.T) {
	f, err := os.Open("testdata/blake2b_vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		size, _ := strconv.Atoi(fields[0])
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 251)
		}
		got := blake2b512(data)
		if hex.EncodeToString(got[:]) != fields[1] {
			t.Errorf("len %d: got %x", size, got)
		}
		n++
	}
	if n < 10 {
		t.Fatalf("only %d vectors", n)
	}
	// RFC 7693 appendix A: BLAKE2b-512("abc")
	abc := blake2b512([]byte("abc"))
	if hex.EncodeToString(abc[:4]) != "ba80a53f" {
		t.Errorf("abc: %x", abc)
	}
}
