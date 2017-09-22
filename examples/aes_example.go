package main

import (
	"crypto/rand"
	"fmt"

	"github.com/lewis-treacy/aes"
)

func main() {
	message := "Hello World!"

	key := make([]byte, 32)
	rand.Read(key)
	fmt.Printf("Key: %X\n\n", key)

	cypher, err := aes.NewCypher(key)
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}

	msg := []byte(message)
	fmt.Printf("Initial message:\n%s\n%X\n\n", msg, msg)

	enc := cypher.Encrypt(msg)
	fmt.Printf("Encryped message:\n%X\n\n", enc)

	dec, err := cypher.Decrypt(enc)
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}
	fmt.Printf("Decryped message:\n%s\n%X\n\n", dec, dec)
}
