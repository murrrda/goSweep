package main

import (
    "crypto/aes"
    "crypto/cipher"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

func main() {
    dir := "test"
    const aes_key = "12345678123456781234567812345678" // 128 bit

    err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            fmt.Println("Error accessing path: ", path, err)
            return err
        }

        if !info.IsDir() && strings.HasSuffix(info.Name(), ".enc") {
            data, err := os.ReadFile(path)
            if err != nil {
                fmt.Println("Error reading file!")
            }

            newFileName := strings.TrimSuffix(path, ".enc")

            file, err := os.Create(newFileName)
            if err != nil {
                fmt.Println(err)
            }
            defer file.Close()

            // decrypt
            aes_key_to_byte := []byte(aes_key)
            aes_key_cipher, _ := aes.NewCipher(aes_key_to_byte)

            gcm, err := cipher.NewGCM(aes_key_cipher)
            if err != nil {
                fmt.Println(err)
                return err
            }

            nonce, cipherText := data[:gcm.NonceSize()], data[gcm.NonceSize():]

            plainText, err := gcm.Open(nil, nonce, cipherText, nil)
            if err != nil {
                fmt.Println(err)
                return err
            }
            
            _, err = file.Write(plainText)
            if err != nil {
                fmt.Println(err)
                return err
            }

            err = os.Remove(path)
            if err != nil {
                fmt.Println(err)
                return err
            }

            fmt.Println("Decryption successful!")
        }
        return err
    })

    if err != nil {
        fmt.Println("Error walking through!")
    }
}

