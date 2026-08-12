package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AES-GCM 加密数据
//
// nonce 长度必须等于 GCM 标准 nonce 长度（12 字节），否则返回错误。
func GCMEncrypt(originText, nonce, additional, key []byte) (cipherText []byte, err error) {
	return gcmEncrypt(originText, nonce, additional, key)
}

// AES-GCM 解密数据
//
// nonce 长度必须等于 GCM 标准 nonce 长度（12 字节），否则返回错误。
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
	// nonce 长度不符时 gcm.Open 内部会直接 panic。密文与 nonce 多来自外部报文
	// （如支付回调），必须提前拦截并以 error 返回，避免打挂调用方进程。
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("aes: invalid nonce length %d, must be %d", len(nonce), gcm.NonceSize())
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
	// nonce 长度不符时 gcm.Seal 内部会直接 panic，此处提前拦截。
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("aes: invalid nonce length %d, must be %d", len(nonce), gcm.NonceSize())
	}
	cipherBytes := gcm.Seal(nil, nonce, originText, additional)
	return cipherBytes, nil
}
