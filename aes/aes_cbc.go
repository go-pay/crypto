package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AES-CBC 加密数据
//
// iv 长度不得小于一个分组（16 字节），超出部分会被忽略。
func CBCEncrypt(originData, key, iv []byte) ([]byte, error) {
	return cbcEncrypt(originData, key, iv)
}

// AES-CBC 解密数据
//
// iv 长度不得小于一个分组（16 字节），secretData 长度必须为分组长度的非零整数倍。
func CBCDecrypt(secretData, key, iv []byte) ([]byte, error) {
	return cbcDecrypt(secretData, key, iv)
}

func cbcEncrypt(originData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// iv 不足一个分组时，下面的 iv[:blockSize] 会 panic。
	if len(iv) < blockSize {
		return nil, fmt.Errorf("aes: invalid iv length %d, must be at least %d", len(iv), blockSize)
	}
	originData = PKCS7Padding(originData, blockSize)
	secretData := make([]byte, len(originData))
	blockMode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	blockMode.CryptBlocks(secretData, originData)
	return secretData, nil
}

func cbcDecrypt(secretData, key, iv []byte) (originByte []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(iv) < blockSize {
		return nil, fmt.Errorf("aes: invalid iv length %d, must be at least %d", len(iv), blockSize)
	}
	// 密文常来自外部输入，长度非分组整数倍时 CryptBlocks 会 panic，此处提前拦截。
	if len(secretData) == 0 || len(secretData)%blockSize != 0 {
		return nil, fmt.Errorf("aes: invalid ciphertext length %d, must be a non-zero multiple of %d", len(secretData), blockSize)
	}
	originByte = make([]byte, len(secretData))
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	blockMode.CryptBlocks(originByte, secretData)
	return PKCS7UnPadding(originByte), nil
}
