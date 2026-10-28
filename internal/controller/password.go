package controller

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Password hashing parameters. The encoded format is:
//
//	pbkdf2-sha256$<iterations>$<salt base64url>$<derived key base64url>
//
// It is deliberately self-describing so the work factor can be raised later
// without invalidating existing hashes.
const (
	passwordHashScheme     = "pbkdf2-sha256"
	passwordHashIterations = 210_000
	passwordSaltBytes      = 16
	passwordKeyBytes       = 32
	minPasswordRunes       = 12
	maxPasswordHashBytes   = 4096
)

// ErrInvalidPasswordHash is returned when an encoded hash is malformed.
var ErrInvalidPasswordHash = errors.New("invalid PBKDF2 password hash")

// HashPassword derives a new encoded PBKDF2-HMAC-SHA256 hash with a fresh
// random salt using the current work factor.
func HashPassword(password string) (string, error) {
	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return encodePasswordHash(password, salt, passwordHashIterations, passwordKeyBytes)
}

func encodePasswordHash(password string, salt []byte, iterations, keyLen int) (string, error) {
	dk := pbkdf2SHA256([]byte(password), salt, iterations, keyLen)
	enc := base64.RawURLEncoding
	return fmt.Sprintf("%s$%d$%s$%s", passwordHashScheme, iterations, enc.EncodeToString(salt), enc.EncodeToString(dk)), nil
}

type parsedPasswordHash struct {
	iterations int
	salt       []byte
	key        []byte
}

func parsePasswordHash(encoded string) (*parsedPasswordHash, error) {
	if len(encoded) == 0 || len(encoded) > maxPasswordHashBytes {
		return nil, ErrInvalidPasswordHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != passwordHashScheme {
		return nil, ErrInvalidPasswordHash
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 10_000 || iterations > 10_000_000 {
		return nil, ErrInvalidPasswordHash
	}
	enc := base64.RawURLEncoding
	salt, err := enc.DecodeString(parts[2])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return nil, ErrInvalidPasswordHash
	}
	key, err := enc.DecodeString(parts[3])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return nil, ErrInvalidPasswordHash
	}
	return &parsedPasswordHash{iterations: iterations, salt: salt, key: key}, nil
}

// ValidatePasswordHash reports whether encoded is a well-formed hash produced
// by the expected scheme.
func ValidatePasswordHash(encoded string) error {
	_, err := parsePasswordHash(encoded)
	return err
}

// VerifyPassword reports whether password matches the encoded hash. The
// comparison is constant time. A malformed hash yields false and an error.
func VerifyPassword(password, encoded string) (bool, error) {
	parsed, err := parsePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	got := pbkdf2SHA256([]byte(password), parsed.salt, parsed.iterations, len(parsed.key))
	return subtle.ConstantTimeCompare(got, parsed.key) == 1, nil
}

// pbkdf2SHA256 implements PBKDF2 (RFC 8018) with HMAC-SHA256 using only the
// standard library.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	const hashLen = sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	var block [4]byte
	for i := 1; i <= numBlocks; i++ {
		block[0] = byte(i >> 24)
		block[1] = byte(i >> 16)
		block[2] = byte(i >> 8)
		block[3] = byte(i)
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(block[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iterations; n++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// HashPasswordForCLI implements the -hash-password mode: it reads one password
// from stdin, enforces the minimum length, and returns the encoded hash.
func HashPasswordForCLI(stdin io.Reader) (string, error) {
	const maxInputBytes = 4096
	data, err := io.ReadAll(io.LimitReader(stdin, maxInputBytes+1))
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(data) > maxInputBytes {
		return "", errors.New("password input too large")
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", errors.New("password must not be empty")
	}
	if !utf8.ValidString(password) {
		return "", errors.New("password must be valid UTF-8")
	}
	if utf8.RuneCountInString(password) < minPasswordRunes {
		return "", fmt.Errorf("password must be at least %d characters", minPasswordRunes)
	}
	return HashPassword(password)
}
