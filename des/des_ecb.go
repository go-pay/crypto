package des

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// checkIVLen iv 不足一个分组时，iv[:blockSize] 会越界 panic，此处提前拦截。
func checkIVLen(iv []byte, blockSize int) error {
	if len(iv) < blockSize {
		return fmt.Errorf("des: invalid iv length %d, must be at least %d", len(iv), blockSize)
	}
	return nil
}

// 3DES-ECB 加密数据
func ECBTripleEncrypt(originData, key, iv []byte) ([]byte, error) {
	data, err := ecbTripleEncrypt(originData, key, iv)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// 3DES-ECB 解密数据
func ECBTripleDecrypt(secretData, key, iv []byte) ([]byte, error) {
	return ecbTripleDecrypt(secretData, key, iv)
}

// DES-ECB 加密数据
func ECBEncrypt(originData, key, iv []byte) ([]byte, error) {
	data, err := ecbEncrypt(originData, key, iv)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// DES-ECB 解密数据
func ECBDecrypt(secretData, key, iv []byte) ([]byte, error) {
	return ecbDecrypt(secretData, key, iv)
}

func ecbTripleEncrypt(originData, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if err = checkIVLen(iv, blockSize); err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	originData = PKCS7Padding(originData, blockSize)
	secretData := make([]byte, len(originData))
	blockMode.CryptBlocks(secretData, originData)
	return secretData, nil
}

func ecbTripleDecrypt(secretData, desKey, iv []byte) (originByte []byte, err error) {
	block, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if err = checkIVLen(iv, blockSize); err != nil {
		return nil, err
	}
	if err = checkCipherLen(secretData, blockSize); err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	originByte = make([]byte, len(secretData))
	blockMode.CryptBlocks(originByte, secretData)
	return PKCS7UnPadding(originByte), nil
}

func ecbEncrypt(originData, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if err = checkIVLen(iv, blockSize); err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	originData = PKCS7Padding(originData, blockSize)
	secretData := make([]byte, len(originData))
	blockMode.CryptBlocks(secretData, originData)
	return secretData, nil
}

func ecbDecrypt(secretData, desKey, iv []byte) (originByte []byte, err error) {
	block, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if err = checkIVLen(iv, blockSize); err != nil {
		return nil, err
	}
	if err = checkCipherLen(secretData, blockSize); err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	originByte = make([]byte, len(secretData))
	blockMode.CryptBlocks(originByte, secretData)
	return PKCS7UnPadding(originByte), nil
}
