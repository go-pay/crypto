package aes

import (
	"bytes"
	"encoding/base64"
	"testing"
)

var (
	secretKey = "JYRn4wbCy8KgVIZJ"
	iv        = "JR3unO2glQuMhUx3"
	// apiV3Key 微信支付 APIv3 密钥长度为 32 字节。
	apiV3Key = "Cj5xC9RXf0GFCKWeD9PyY1ZWLgionbvx"
	// gcmNonce AES-GCM 的 nonce 固定为 12 字节。
	gcmNonce = "gopaynonce12"

	originData = "www.gopay.ink"
)

func TestAesECBEncryptDecrypt(t *testing.T) {
	encryptData, err := ECBEncrypt([]byte(originData), []byte(secretKey))
	if err != nil {
		t.Fatalf("ECBEncrypt: %v", err)
	}
	// 固定密钥下的密文应保持稳定，防止填充等实现细节被无意改动。
	const want = "LVVbZok51xycTkL0M6KbYA=="
	if got := base64.StdEncoding.EncodeToString(encryptData); got != want {
		t.Errorf("ECB 密文 = %s, 期望 %s", got, want)
	}

	origin, err := ECBDecrypt(encryptData, []byte(secretKey))
	if err != nil {
		t.Fatalf("ECBDecrypt: %v", err)
	}
	if string(origin) != originData {
		t.Errorf("ECB 解密 = %q, 期望 %q", origin, originData)
	}
}

func TestAesCBCEncryptDecrypt(t *testing.T) {
	encryptData, err := CBCEncrypt([]byte(originData), []byte(secretKey), []byte(iv))
	if err != nil {
		t.Fatalf("CBCEncrypt: %v", err)
	}
	const want = "Jk1ZL/hvMC1eoFgqU8YdSw=="
	if got := base64.StdEncoding.EncodeToString(encryptData); got != want {
		t.Errorf("CBC 密文 = %s, 期望 %s", got, want)
	}

	origin, err := CBCDecrypt(encryptData, []byte(secretKey), []byte(iv))
	if err != nil {
		t.Fatalf("CBCDecrypt: %v", err)
	}
	if string(origin) != originData {
		t.Errorf("CBC 解密 = %q, 期望 %q", origin, originData)
	}
}

func TestEncryptGCM(t *testing.T) {
	data := `我是要加密的数据`
	additional := "transaction"

	ciphertext, err := GCMEncrypt([]byte(data), []byte(gcmNonce), []byte(additional), []byte(apiV3Key))
	if err != nil {
		t.Fatalf("GCMEncrypt: %v", err)
	}
	const want = "O9EOFzUdQESzEGqSo511CbQmt7ZlPuX/yg8n+agktdns0kFG2L0BCg=="
	if got := base64.StdEncoding.EncodeToString(ciphertext); got != want {
		t.Errorf("GCM 密文 = %s, 期望 %s", got, want)
	}

	decryptBytes, err := GCMDecrypt(ciphertext, []byte(gcmNonce), []byte(additional), []byte(apiV3Key))
	if err != nil {
		t.Fatalf("GCMDecrypt: %v", err)
	}
	if string(decryptBytes) != data {
		t.Errorf("GCM 解密 = %q, 期望 %q", decryptBytes, data)
	}

	// AEAD 完整性：附加数据或密文被篡改都必须解密失败。
	if _, err = GCMDecrypt(ciphertext, []byte(gcmNonce), []byte("other"), []byte(apiV3Key)); err == nil {
		t.Error("附加数据不匹配时应解密失败")
	}
	tampered := bytes.Clone(ciphertext)
	tampered[0] ^= 0xff
	if _, err = GCMDecrypt(tampered, []byte(gcmNonce), []byte(additional), []byte(apiV3Key)); err == nil {
		t.Error("密文被篡改时应解密失败")
	}
}

// TestGCMInvalidNonce nonce 长度不合法时必须返回 error，而不是 panic。
// 微信支付回调中的 nonce 来自外部报文，若直接 panic 会打挂商户进程。
func TestGCMInvalidNonce(t *testing.T) {
	for _, nonce := range []string{"", "123456", "0123456789abc"} {
		if _, err := GCMEncrypt([]byte(originData), []byte(nonce), nil, []byte(apiV3Key)); err == nil {
			t.Errorf("GCMEncrypt 在 nonce 长度 %d 时应返回错误", len(nonce))
		}
		if _, err := GCMDecrypt([]byte("whatever-ciphertext-bytes"), []byte(nonce), nil, []byte(apiV3Key)); err == nil {
			t.Errorf("GCMDecrypt 在 nonce 长度 %d 时应返回错误", len(nonce))
		}
	}
	if _, err := GCMEncrypt([]byte(originData), []byte(gcmNonce), nil, []byte("short-key")); err == nil {
		t.Error("密钥长度不合法时应返回错误")
	}
}

// TestInvalidCipherLen 密文长度非分组整数倍时必须返回 error，而不是 panic。
func TestInvalidCipherLen(t *testing.T) {
	for _, bad := range [][]byte{nil, {}, []byte("short"), bytes.Repeat([]byte("a"), 17)} {
		if _, err := ECBDecrypt(bad, []byte(secretKey)); err == nil {
			t.Errorf("ECBDecrypt 在密文长度 %d 时应返回错误", len(bad))
		}
		if _, err := CBCDecrypt(bad, []byte(secretKey), []byte(iv)); err == nil {
			t.Errorf("CBCDecrypt 在密文长度 %d 时应返回错误", len(bad))
		}
	}
}

// TestInvalidIV iv 短于一个分组时必须返回 error，而不是越界 panic。
func TestInvalidIV(t *testing.T) {
	if _, err := CBCEncrypt([]byte(originData), []byte(secretKey), []byte("shortiv")); err == nil {
		t.Error("CBCEncrypt 在 iv 过短时应返回错误")
	}
	if _, err := CBCDecrypt(bytes.Repeat([]byte("a"), 16), []byte(secretKey), nil); err == nil {
		t.Error("CBCDecrypt 在 iv 为空时应返回错误")
	}
	// iv 长于一个分组时取前 16 字节，保持既有行为。
	longIV := []byte(iv + "-extra-bytes")
	got, err := CBCEncrypt([]byte(originData), []byte(secretKey), longIV)
	if err != nil {
		t.Fatalf("CBCEncrypt(长 iv): %v", err)
	}
	want, _ := CBCEncrypt([]byte(originData), []byte(secretKey), []byte(iv))
	if !bytes.Equal(got, want) {
		t.Error("iv 超出一个分组的部分应被忽略")
	}
}

// TestUnPaddingEdgeCases 去填充函数对非法输入必须原样返回，不得越界 panic。
func TestUnPaddingEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"空输入", []byte{}, []byte{}},
		{"填充数超过长度", []byte{0x01, 0x0f}, []byte{0x01, 0x0f}},
		{"填充数为 0", []byte{0x01, 0x00}, []byte{0x01, 0x00}},
		{"正常填充", []byte{0x61, 0x02, 0x02}, []byte{0x61}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCS7UnPadding(bytes.Clone(tt.in)); !bytes.Equal(got, tt.want) {
				t.Errorf("PKCS7UnPadding(%x) = %x, 期望 %x", tt.in, got, tt.want)
			}
			if got := PKCS5UnPadding(bytes.Clone(tt.in)); !bytes.Equal(got, tt.want) {
				t.Errorf("PKCS5UnPadding(%x) = %x, 期望 %x", tt.in, got, tt.want)
			}
		})
	}
	// 填充数大于 16 时 PKCS7UnPadding 原样返回（数据未按 PKCS7 填充）。
	in := bytes.Repeat([]byte{0x20}, 32)
	if got := PKCS7UnPadding(bytes.Clone(in)); !bytes.Equal(got, in) {
		t.Error("填充数大于 16 时应原样返回")
	}
}

// TestPaddingRoundTrip 填充与去填充在各长度下应能还原原文。
func TestPaddingRoundTrip(t *testing.T) {
	for n := 1; n <= 40; n++ {
		data := bytes.Repeat([]byte{0x61}, n)
		padded := PKCS7Padding(bytes.Clone(data), 16)
		if len(padded)%16 != 0 {
			t.Fatalf("长度 %d 填充后 = %d，非 16 的整数倍", n, len(padded))
		}
		if got := PKCS7UnPadding(padded); !bytes.Equal(got, data) {
			t.Errorf("长度 %d 往返 = %x, 期望 %x", n, got, data)
		}
	}
}
