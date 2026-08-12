package des

import "bytes"

// PKCS5Padding 加密填充模式（添加补全码）
// 加密时，如果加密bytes的length不是blockSize的整数倍，需要在最后面添加填充byte
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	paddingCount := blockSize - len(ciphertext)%blockSize //需要padding的数目
	paddingBytes := []byte{byte(paddingCount)}
	padtext := bytes.Repeat(paddingBytes, paddingCount) //生成填充的文本
	return append(ciphertext, padtext...)
}

// PKCS5UnPadding 解密填充模式（去除补全码）
// 解密时，需要在最后面去掉加密时添加的填充byte
//
// origData 为空、或填充数大于数据长度（数据未按 PKCS5 填充）时原样返回，不再越界 panic。
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	if length == 0 {
		return origData
	}
	unpadding := int(origData[length-1]) //找到Byte数组最后的填充byte
	if unpadding > length {
		return origData
	}
	return origData[:(length - unpadding)] //只截取返回有效数字内的byte数组
}

// PKCS7Padding 加密填充模式（添加补全码）
// 加密时，如果加密bytes的length不是blockSize的整数倍，需要在最后面添加填充byte
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	paddingCount := blockSize - len(ciphertext)%blockSize //需要padding的数目
	paddingBytes := []byte{byte(paddingCount)}
	padtext := bytes.Repeat(paddingBytes, paddingCount) //生成填充的文本
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding 解密填充模式（去除补全码）
// 解密时，需要在最后面去掉加密时添加的填充byte
//
// origData 为空、或填充数大于数据长度（数据未按 PKCS7 填充）时原样返回，不再越界 panic。
func PKCS7UnPadding(origData []byte) (bs []byte) {
	length := len(origData)
	if length == 0 {
		return origData
	}
	unPaddingNumber := int(origData[length-1]) // 找到Byte数组最后的填充byte 数字
	if unPaddingNumber <= 16 && unPaddingNumber <= length {
		bs = origData[:(length - unPaddingNumber)] // 只截取返回有效数字内的byte数组
	} else {
		bs = origData
	}
	return
}
