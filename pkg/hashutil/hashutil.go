package hashutil

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashResult holds precomputed hashes of a single file.
type HashResult struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// HashFile computes MD5, SHA1, and SHA256 of the file at path in a single pass.
func HashFile(path string) (*HashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("hashutil: open %s: %w", path, err)
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()

	w := io.MultiWriter(hMD5, hSHA1, hSHA256)
	if _, err := io.Copy(w, f); err != nil {
		return nil, fmt.Errorf("hashutil: read %s: %w", path, err)
	}

	return &HashResult{
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
		SHA1:   hex.EncodeToString(hSHA1.Sum(nil)),
		SHA256: hex.EncodeToString(hSHA256.Sum(nil)),
	}, nil
}

// SHA256File computes only SHA256 of the file at path.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hashutil: open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashutil: read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
