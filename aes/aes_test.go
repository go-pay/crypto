package aes

import (
	"encoding/base64"
	"log"
	"testing"
)

var (
	secretKey = "JYRn4wbCy8KgVIZJ"
	iv        = "JR3unO2glQuMhUx3"
)

func TestAesECBEncryptDecrypt(t *testing.T) {
	originData := "www.gopay.ink"
	log.Println("originData:", originData)
	encryptData, err := ECBEncrypt([]byte(originData), []byte(secretKey))
	if err != nil {
		log.Println("AesCBCEncryptToString:", err)
		return
	}

	toString := base64.StdEncoding.EncodeToString(encryptData)
	log.Println("encryptData_EncodeToString:", toString)
	bs, err := base64.StdEncoding.DecodeString(toString)
	if err != nil {
		log.Println("base64.StdEncoding.DecodeString:", err)
		return
	}

	origin, err := ECBDecrypt(bs, []byte(secretKey))
	if err != nil {
		log.Println("AesDecryptToBytes:", err)
		return
	}
	log.Println("origin:", string(origin))
}

func TestAesCBCEncryptDecrypt(t *testing.T) {
	originData := "www.gopay.ink"
	log.Println("originData:", originData)
	encryptData, err := CBCEncrypt([]byte(originData), []byte(secretKey), []byte(iv))
	if err != nil {
		log.Println("CBCEncrypt:", err)
		return
	}

	toString := base64.StdEncoding.EncodeToString(encryptData)
	log.Println("encryptData_EncodeToString:", toString)
	bs, err := base64.StdEncoding.DecodeString(toString)
	if err != nil {
		log.Println("base64.StdEncoding.DecodeString:", err)
		return
	}

	origin, err := CBCDecrypt(bs, []byte(secretKey), []byte(iv))
	if err != nil {
		log.Println("CBCDecrypt:", err)
		return
	}
	log.Println("origin:", string(origin))
}

func TestEncryptGCM(t *testing.T) {
	data := `我是要加密的数据`
	additional := "transaction"
	apiV3key := "Cj5xC9RXf0GFCKWeD9PyY1ZWLgionbvx"
	log.Println("原始数据：", data)
	// 加密
	ciphertext, err := GCMEncrypt([]byte(data), []byte("123456"), []byte(additional), []byte(apiV3key))
	if err != nil {
		log.Println(err)
		return
	}
	encryptText := base64.StdEncoding.EncodeToString(ciphertext)
	log.Println("加密后：", encryptText)

	// 解密
	cipherBytes, _ := base64.StdEncoding.DecodeString(encryptText)
	decryptBytes, err := GCMDecrypt(cipherBytes, []byte("123456"), []byte(additional), []byte(apiV3key))
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("解密后：", string(decryptBytes))
}
