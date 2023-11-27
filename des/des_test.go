package des

import (
	"log"
	"testing"
)

var (
	secretKey1 = "hehehaha"
	iv1        = "12378945"

	secretKey = "GYBh3Rmey7nNzR/NpV0vAw=="
	iv        = "JR3unO2glQuMhUx3"
)

func TestDesCBCEncrypt_Decrypt(t *testing.T) {
	originData := "www.gopay.ink"
	log.Println("originData:", originData)
	encryptData, err := CBCEncrypt([]byte(originData), []byte(secretKey1))
	if err != nil {
		log.Println("DesCBCEncryptData:", err)
		return
	}
	log.Println("encryptData:", string(encryptData))
	origin, err := CBCDecrypt(encryptData, []byte(secretKey1))
	if err != nil {
		log.Println("DesCBCDecryptData:", err)
		return
	}
	log.Println("origin:", string(origin))
}

func TestDesECBEncrypt_Decrypt(t *testing.T) {
	originData := "www.gopay.ink"
	log.Println("originData:", originData)
	encryptData, err := ECBEncrypt([]byte(originData), []byte(secretKey1), []byte(iv1))
	if err != nil {
		log.Println("DesCBCEncryptIvData:", err)
		return
	}
	log.Println("encryptData:", string(encryptData))
	origin, err := ECBDecrypt(encryptData, []byte(secretKey1), []byte(iv1))
	if err != nil {
		log.Println("DesCBCDecryptIvData:", err)
		return
	}
	log.Println("origin:", string(origin))
}

func TestDesCBCTripleEncrypt_Decrypt(t *testing.T) {
	originData := "www.gopay.ink"
	log.Println("originData:", originData)
	encryptData, err := CBCTripleEncrypt([]byte(originData), []byte(secretKey))
	if err != nil {
		log.Println("DesCBCEncryptData:", err)
		return
	}
	log.Println("encryptData:", string(encryptData))
	origin, err := CBCTripleDecrypt(encryptData, []byte(secretKey))
	if err != nil {
		log.Println("DesCBCDecryptData:", err)
		return
	}
	log.Println("origin:", string(origin))
}

func TestDesECBTripleEncrypt_Decrypt(t *testing.T) {
	originData := "www.gopay.ink"
	log.Println("originData:", originData)
	encryptData, err := ECBTripleEncrypt([]byte(originData), []byte(secretKey), []byte(iv))
	if err != nil {
		log.Println("DesCBCEncryptIvData:", err)
		return
	}
	log.Println("encryptData:", string(encryptData))
	origin, err := ECBTripleDecrypt(encryptData, []byte(secretKey), []byte(iv))
	if err != nil {
		log.Println("DesCBCDecryptIvData:", err)
		return
	}
	log.Println("origin:", string(origin))
}
