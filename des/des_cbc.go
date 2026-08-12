package des

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// checkCipherLen 密文长度必须为分组长度的非零整数倍，否则 CryptBlocks 会 panic。
// 密文常来自外部输入，这里提前拦截并以 error 返回。
func checkCipherLen(secretData []byte, blockSize int) error {
	if len(secretData) == 0 || len(secretData)%blockSize != 0 {
		return fmt.Errorf("des: invalid ciphertext length %d, must be a non-zero multiple of %d", len(secretData), blockSize)
	}
	return nil
}

// 3DES-CBC 加密数据
func CBCTripleEncrypt(originData, key []byte) ([]byte, error) {
	return cbcTripleEncrypt(originData, key)
}

// 3DES-CBC 解密数据
func CBCTripleDecrypt(secretData, key []byte) ([]byte, error) {
	return cbcTripleDecrypt(secretData, key)
}

// DES-CBC 加密数据
func CBCEncrypt(originData, key []byte) ([]byte, error) {
	return cbcEncrypt(originData, key)
}

// DES-CBC 解密数据
func CBCDecrypt(secretData, key []byte) ([]byte, error) {
	return cbcDecrypt(secretData, key)
}

func cbcTripleEncrypt(originData, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	originData = PKCS7Padding(originData, blockSize)
	secretData := make([]byte, len(originData))
	blockMode.CryptBlocks(secretData, originData)
	return secretData, nil
}

func cbcTripleDecrypt(secretData, key []byte) (originByte []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if err = checkCipherLen(secretData, blockSize); err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	originByte = make([]byte, len(secretData))
	blockMode.CryptBlocks(originByte, secretData)
	return PKCS7UnPadding(originByte), nil
}

func cbcEncrypt(originData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	originData = PKCS7Padding(originData, blockSize)
	secretData := make([]byte, len(originData))
	blockMode.CryptBlocks(secretData, originData)
	return secretData, nil
}

func cbcDecrypt(secretData, key []byte) (originByte []byte, err error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if err = checkCipherLen(secretData, blockSize); err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	originByte = make([]byte, len(secretData))
	blockMode.CryptBlocks(originByte, secretData)
	return PKCS7UnPadding(originByte), nil
}
