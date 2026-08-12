package sm2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/go-pay/crypto/sm3"
)

// cipherASN1 是 SM2 密文的 ASN.1 结构（GM/T 0009-2012 SM2Cipher）：
//
//	SM2Cipher ::= SEQUENCE {
//	    XCoordinate  INTEGER,
//	    YCoordinate  INTEGER,
//	    HASH         OCTET STRING SIZE(32),   -- C3
//	    CipherText   OCTET STRING             -- C2
//	}
//
// 该编码与 tjfoc/gmsm 的 EncryptAsn1 / DecryptAsn1 字节级兼容，
// 也是招商银行等网关要求的数字信封格式。
type cipherASN1 struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

// Encrypt 用公钥加密明文，返回 C1C3C2 顺序、ASN.1 DER 编码的密文
// （GB/T 32918.4-2016 6.1）。
func Encrypt(pub *PublicKey, plain []byte) ([]byte, error) {
	if err := CheckPublicKey(pub); err != nil {
		return nil, err
	}
	if len(plain) == 0 {
		return nil, errors.New("sm2: 待加密明文不能为空")
	}
	for {
		// A1: 产生随机数 k ∈ [1, n-1]
		k, err := randFieldElement(rand.Reader)
		if err != nil {
			return nil, err
		}
		// A2: C1 = [k]G
		x1, y1 := sm2Curve.ScalarBaseMult(k.Bytes())
		// A4: [k]P_B = (x2, y2)
		x2, y2 := sm2Curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		x2b, y2b := pad32(x2.Bytes()), pad32(y2.Bytes())

		// A5: t = KDF(x2 || y2, klen)，t 全 0 时需重选 k
		t, ok := kdf(len(plain), x2b, y2b)
		if !ok {
			continue
		}
		// A6: C2 = M ⊕ t
		c2 := make([]byte, len(plain))
		subtle.XORBytes(c2, plain, t)

		// A7: C3 = SM3(x2 || M || y2)
		h := sm3.New()
		_, _ = h.Write(x2b)
		_, _ = h.Write(plain)
		_, _ = h.Write(y2b)
		c3 := h.Sum(nil)

		return asn1.Marshal(cipherASN1{x1, y1, c3, c2})
	}
}

// Decrypt 用私钥解密 ASN.1 DER 编码的 C1C3C2 密文（GB/T 32918.4-2016 7.1）。
func Decrypt(priv *PrivateKey, cipherText []byte) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, ErrInvalidPrivateKey
	}
	var c cipherASN1
	rest, err := asn1.Unmarshal(cipherText, &c)
	if err != nil {
		return nil, errors.New("sm2: 密文 ASN.1 解析失败: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("sm2: 密文 ASN.1 存在多余数据")
	}
	if len(c.HASH) != 32 {
		return nil, ErrInvalidCipher
	}
	if len(c.CipherText) == 0 {
		return nil, ErrInvalidCipher
	}
	// B1: 校验 C1 是否为曲线上的点，防止无效曲线攻击。
	if !isOnCurve(c.XCoordinate, c.YCoordinate) {
		return nil, ErrInvalidCipher
	}

	// B3: [d]C1 = (x2, y2)
	x2, y2 := sm2Curve.ScalarMult(c.XCoordinate, c.YCoordinate, pad32(priv.D.Bytes()))
	x2b, y2b := pad32(x2.Bytes()), pad32(y2.Bytes())

	// B4: t = KDF(x2 || y2, klen)
	t, ok := kdf(len(c.CipherText), x2b, y2b)
	if !ok {
		return nil, ErrInvalidCipher
	}
	// B5: M' = C2 ⊕ t
	plain := make([]byte, len(c.CipherText))
	subtle.XORBytes(plain, c.CipherText, t)

	// B6: 校验 u = SM3(x2 || M' || y2) 是否等于 C3
	h := sm3.New()
	_, _ = h.Write(x2b)
	_, _ = h.Write(plain)
	_, _ = h.Write(y2b)
	if subtle.ConstantTimeCompare(h.Sum(nil), c.HASH) != 1 {
		return nil, ErrInvalidCipher
	}
	return plain, nil
}

// EncryptC1C3C2 用公钥加密明文，返回 0x04 || C1 || C3 || C2 的拼接格式密文
// （即未做 ASN.1 编码的裸拼接形式，部分网关使用该格式）。
func EncryptC1C3C2(pub *PublicKey, plain []byte) ([]byte, error) {
	der, err := Encrypt(pub, plain)
	if err != nil {
		return nil, err
	}
	var c cipherASN1
	if _, err = asn1.Unmarshal(der, &c); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+64+32+len(c.CipherText))
	out = append(out, 0x04)
	out = append(out, pad32(c.XCoordinate.Bytes())...)
	out = append(out, pad32(c.YCoordinate.Bytes())...)
	out = append(out, c.HASH...)
	out = append(out, c.CipherText...)
	return out, nil
}

// DecryptC1C3C2 用私钥解密 0x04 || C1 || C3 || C2 拼接格式的密文。
func DecryptC1C3C2(priv *PrivateKey, data []byte) ([]byte, error) {
	// 1 字节前缀 + 64 字节 C1 + 32 字节 C3，之后至少 1 字节 C2。
	if len(data) < 1+64+32+1 || data[0] != 0x04 {
		return nil, ErrInvalidCipher
	}
	body := data[1:]
	der, err := asn1.Marshal(cipherASN1{
		XCoordinate: new(big.Int).SetBytes(body[:32]),
		YCoordinate: new(big.Int).SetBytes(body[32:64]),
		HASH:        body[64:96],
		CipherText:  body[96:],
	})
	if err != nil {
		return nil, err
	}
	return Decrypt(priv, der)
}
