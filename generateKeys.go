package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Function to generate RSA key pair
func generateRSAKeys(bits int) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	// Save private key to PEM file
	privateKeyFile, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	_, err = privateKeyFile.Write(privateKeyPEM)
	if err != nil {
		return err
	}
	fmt.Println("Private key saved to private.pem")

	// Extract public key from private key
	publicKey := &privateKey.PublicKey

	// Save public key to PEM file
	publicKeyFile, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	_, err = publicKeyFile.Write(publicKeyPEM)
	if err != nil {
		return err
	}
	fmt.Println("Public key saved to public.pem")

	return nil
}

func main() {
	err := generateRSAKeys(2048) // Use 2048 or 4096 for strong encryption
	if err != nil {
		fmt.Println("Error generating keys:", err)
	} else {
		fmt.Println("RSA key pair generated successfully!")
	}
}
