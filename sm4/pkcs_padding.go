package sm4

import (
	"bytes"
	"errors"
)

// PKCS7Padding 按 PKCS#7 对明文补齐到 blockSize 的整数倍。
// 明文长度已是整数倍时会补一个完整分组，以保证去填充可逆。
func PKCS7Padding(originData []byte, blockSize int) []byte {
	paddingCount := blockSize - len(originData)%blockSize
	return append(originData, bytes.Repeat([]byte{byte(paddingCount)}, paddingCount)...)
}

// PKCS7UnPadding 去除 PKCS#7 填充。
// 与 aes 包中的同名函数不同，此处对填充做严格校验，非法填充返回错误，
// 避免把损坏的密文当作有效明文返回。
func PKCS7UnPadding(originData []byte, blockSize int) ([]byte, error) {
	length := len(originData)
	if length == 0 {
		return nil, errors.New("sm4: 待去填充数据为空")
	}
	if length%blockSize != 0 {
		return nil, errors.New("sm4: 待去填充数据长度不是分组长度的整数倍")
	}
	paddingCount := int(originData[length-1])
	if paddingCount == 0 || paddingCount > blockSize || paddingCount > length {
		return nil, errors.New("sm4: PKCS#7 填充值非法")
	}
	// 校验全部填充字节是否一致。
	for _, b := range originData[length-paddingCount:] {
		if int(b) != paddingCount {
			return nil, errors.New("sm4: PKCS#7 填充内容不一致")
		}
	}
	return originData[:length-paddingCount], nil
}
