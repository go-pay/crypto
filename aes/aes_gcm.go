package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AES-GCM 加密数据
func GCMEncrypt(originText, nonce, additional, key []byte) (cipherText []byte, err error) {
	return gcmEncrypt(originText, nonce, additional, key)
}

// AES-GCM 解密数据
func GCMDecrypt(cipherText, nonce, additional, key []byte) ([]byte, error) {
	return gcmDecrypt(cipherText, nonce, additional, key)
}

func gcmDecrypt(secretData, nonce, additional, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM(),error:%w", err)
	}
	originByte, err := gcm.Open(nil, nonce, secretData, additional)
	if err != nil {
		return nil, err
	}
	return originByte, nil
}

func gcmEncrypt(originText, nonce, additional, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM(),error:%w", err)
	}
	cipherBytes := gcm.Seal(nil, nonce, originText, additional)
	return cipherBytes, nil
}
