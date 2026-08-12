package sm4

import (
	"crypto/cipher"
	"errors"
)

// ECBEncrypt SM4-ECB 加密数据，明文按 PKCS#7 填充，key 需为 16 字节。
//
// 注意：ECB 模式相同明文分组会产生相同密文分组，不隐藏数据模式，
// 仅在对接方协议明确要求时使用（如招商银行聚合支付的敏感字段加密）；
// 新设计请优先选择 CBC 或 GCM。
func ECBEncrypt(originData, key []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := PKCS7Padding(originData, block.BlockSize())
	secretData := make([]byte, len(plain))
	newECBEncrypter(block).CryptBlocks(secretData, plain)
	return secretData, nil
}

// ECBDecrypt SM4-ECB 解密数据并去除 PKCS#7 填充，key 需为 16 字节。
func ECBDecrypt(secretData, key []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(secretData) == 0 || len(secretData)%block.BlockSize() != 0 {
		return nil, errors.New("sm4: 密文长度不是分组长度的整数倍")
	}
	originData := make([]byte, len(secretData))
	newECBDecrypter(block).CryptBlocks(originData, secretData)
	return PKCS7UnPadding(originData, block.BlockSize())
}

// ===========

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{b: b, blockSize: b.BlockSize()}
}

type ecbEncrypter ecb

// newECBEncrypter 返回以 ECB 模式加密的 BlockMode。
func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("sm4: 输入不是完整分组")
	}
	if len(dst) < len(src) {
		panic("sm4: 输出缓冲区小于输入")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// newECBDecrypter 返回以 ECB 模式解密的 BlockMode。
func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("sm4: 输入不是完整分组")
	}
	if len(dst) < len(src) {
		panic("sm4: 输出缓冲区小于输入")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
