// Package leak is the staging leak check. It answers one question: how many
// real production values are on this staging database?
//
// Hash samples the columns scan flags on production and keeps keyed hashes of
// the values, under a key only the customer holds. Compare reads those columns
// whole on staging, hashes what it finds the same way, and counts the matches.
// Neither step keeps or prints a value, and a report holds counts only.
package leak

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/ProdMask/ProdMask/pkg/model"
)

const (
	keyBytes       = 32
	minKeyDistinct = 10
	maxKeyFile     = 4096
	saltLen        = 16
	hashLen        = 16
	keyCheckLen    = 8

	hashLabel     = "prodmask leak-check v1"
	keyCheckLabel = "prodmask leak-check key check v1"
)

// The errors a key can give. None quotes what it read, which may be a key.
var (
	ErrKeyFormat = errors.New("a key is at least 64 hex characters: make one with prodmask leak-check key, or openssl rand -hex 32")
	ErrKeyUTF16  = errors.New("the key file isn't plain text; it looks like UTF-16, which PowerShell's > writes: make one with prodmask leak-check key")
)

// Key is the secret the hashes are made under. It prints as [key]. The bytes
// sit behind a function, so even a verb or a struct that skips Format can't
// print them: fmt follows pointers, and doesn't call functions.
type Key struct{ secret func() []byte }

// Format keeps a key out of anything that prints one by accident.
func (Key) Format(f fmt.State, _ rune) { io.WriteString(f, "[key]") }

// ParseKey reads a key as a key file or $PRODMASK_LEAK_KEY holds it: hex, with
// whitespace and a UTF-8 BOM around it allowed. Anything else is refused,
// passphrases above all, the one way a keyed hash becomes guessable.
func ParseKey(text []byte) (Key, error) {
	text = bytes.TrimPrefix(text, []byte("\xef\xbb\xbf"))
	if bytes.IndexByte(text, 0) >= 0 {
		return Key{}, ErrKeyUTF16
	}
	s := bytes.ToLower(bytes.TrimSpace(text))
	if len(s) < 2*keyBytes || len(s)%2 != 0 {
		return Key{}, ErrKeyFormat
	}
	distinct := map[byte]bool{}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return Key{}, ErrKeyFormat
		}
		distinct[c] = true
	}
	if len(distinct) < minKeyDistinct {
		return Key{}, ErrKeyFormat
	}
	b := make([]byte, len(s)/2)
	if _, err := hex.Decode(b, s); err != nil {
		return Key{}, ErrKeyFormat
	}
	return Key{secret: func() []byte { return b }}, nil
}

// ReadKeyFile reads a key file. Its errors don't quote the path, which may be
// a key typed in the wrong place. worldReadable says others can read the file,
// which only means something outside Windows.
func ReadKeyFile(path string) (k Key, worldReadable bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return Key{}, false, errors.New("can't read the file given to --key-file")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Key{}, false, errors.New("can't read the file given to --key-file")
	}
	text, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return Key{}, false, errors.New("can't read the file given to --key-file")
	}
	if len(text) > maxKeyFile {
		return Key{}, false, ErrKeyFormat
	}
	k, err = ParseKey(text)
	return k, fi.Mode().Perm()&0o077 != 0, err
}

// WriteNewKey makes a key and writes it to a new file, owner-only where the
// system has that. It never overwrites a file: that would orphan the hashes
// made under the old key.
func WriteNewKey(path string) error {
	b := make([]byte, keyBytes)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s\n", hex.EncodeToString(b))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// keyCheck is what a file records so compare can refuse a wrong key, which
// would otherwise read as a zero: the worst possible silent failure.
func (k Key) keyCheck(salt []byte) []byte {
	h := hmac.New(sha256.New, k.secret())
	h.Write([]byte(keyCheckLabel))
	h.Write([]byte{0})
	h.Write(salt)
	return h.Sum(nil)[:keyCheckLen]
}

// hasher makes the hashes of one file. The salt keeps one key used across
// checks from giving equal hashes in different files. The location in each
// message keeps the same value in two columns from giving equal hashes, so a
// file can't link a person across columns.
type hasher struct {
	h    hash.Hash
	salt []byte
	sum  [sha256.Size]byte
}

func (k Key) hasher(salt []byte) *hasher {
	return &hasher{h: hmac.New(sha256.New, k.secret()), salt: salt}
}

// prefix is what goes before the value in every hash of one kind in one
// location.
func (hs *hasher) prefix(table, column, metaKey string, kind model.LeakKind) []byte {
	var b bytes.Buffer
	b.WriteString(hashLabel)
	b.WriteByte(0)
	b.Write(hs.salt)
	for _, s := range []string{table, column, metaKey, string(kind)} {
		b.WriteByte(0)
		b.WriteString(s)
	}
	b.WriteByte(0)
	return b.Bytes()
}

// of hashes a normalised value, cut to 16 bytes: plenty against chance
// collisions at these sizes.
func (hs *hasher) of(prefix []byte, value string) [hashLen]byte {
	hs.h.Reset()
	hs.h.Write(prefix)
	io.WriteString(hs.h, value)
	var out [hashLen]byte
	copy(out[:], hs.h.Sum(hs.sum[:0]))
	return out
}
