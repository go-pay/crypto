package sm4

import (
	"crypto/cipher"
	"errors"
)

// CBCEncrypt SM4-CBC 加密数据，明文按 PKCS#7 填充。
// key 与 iv 均需为 16 字节。
func CBCEncrypt(originData, key, iv []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, errors.New("sm4: iv 长度应为 16 字节")
	}
	plain := PKCS7Padding(originData, block.BlockSize())
	secretData := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(secretData, plain)
	return secretData, nil
}

// CBCDecrypt SM4-CBC 解密数据并去除 PKCS#7 填充。
// key 与 iv 均需为 16 字节。
func CBCDecrypt(secretData, key, iv []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, errors.New("sm4: iv 长度应为 16 字节")
	}
	if len(secretData) == 0 || len(secretData)%block.BlockSize() != 0 {
		return nil, errors.New("sm4: 密文长度不是分组长度的整数倍")
	}
	originData := make([]byte, len(secretData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(originData, secretData)
	return PKCS7UnPadding(originData, block.BlockSize())
}
