package sm2

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// oidSM2 SM2 公钥算法标识（id-ecPublicKey，1.2.840.10045.2.1）。
var oidSM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// oidNamedCurveSM2 SM2 推荐曲线标识（1.2.156.10197.1.301）。
var oidNamedCurveSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}

// pkixPublicKey 是 X.509 SubjectPublicKeyInfo 结构。
type pkixPublicKey struct {
	Algo struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	BitString asn1.BitString
}

// GenerateKey 生成一对新的 SM2 密钥。
func GenerateKey() (*PrivateKey, error) {
	for {
		d, err := randFieldElement(rand.Reader)
		if err != nil {
			return nil, err
		}
		// 私钥有效区间为 [1, n-2]。
		if d.Cmp(new(big.Int).Sub(sm2Curve.N, big.NewInt(1))) >= 0 {
			continue
		}
		return newPrivateKey(d)
	}
}

// newPrivateKey 由标量 d 装配私钥并推导公钥。
func newPrivateKey(d *big.Int) (*PrivateKey, error) {
	if d == nil || d.Sign() <= 0 || d.Cmp(new(big.Int).Sub(sm2Curve.N, big.NewInt(1))) >= 0 {
		return nil, ErrInvalidPrivateKey
	}
	priv := &PrivateKey{D: d}
	priv.Curve = sm2Curve
	priv.X, priv.Y = sm2Curve.ScalarBaseMult(pad32(d.Bytes()))
	return priv, nil
}

// ParsePrivateKeyHex 从 64 字符 HEX 字符串解析 SM2 私钥。
//
// 国密标准私钥为 32 字节大端整数，转 HEX 即 64 字符。多数银行网关
// （如招商银行聚合支付）以该形式下发商户私钥。
func ParsePrivateKeyHex(hexKey string) (*PrivateKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, errors.New("sm2: 私钥 HEX 解析失败: " + err.Error())
	}
	return ParsePrivateKeyBytes(raw)
}

// ParsePrivateKeyBytes 从 32 字节大端整数解析 SM2 私钥。
func ParsePrivateKeyBytes(raw []byte) (*PrivateKey, error) {
	if len(raw) != 32 {
		return nil, fmt.Errorf("sm2: 私钥长度应为 32 字节，实际 %d 字节", len(raw))
	}
	return newPrivateKey(new(big.Int).SetBytes(raw))
}

// MarshalPrivateKeyHex 将私钥编码为 64 字符小写 HEX 字符串。
func MarshalPrivateKeyHex(priv *PrivateKey) string {
	return hex.EncodeToString(pad32(priv.D.Bytes()))
}

// ParsePublicKeyDER 从 ASN.1 DER 编码的 SubjectPublicKeyInfo 解析 SM2 公钥。
func ParsePublicKeyDER(der []byte) (*PublicKey, error) {
	var spki pkixPublicKey
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, errors.New("sm2: 公钥 ASN.1 解析失败: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("sm2: 公钥 ASN.1 存在多余数据")
	}
	if !spki.Algo.Algorithm.Equal(oidSM2) {
		return nil, errors.New("sm2: 公钥算法标识不是 SM2/ecPublicKey")
	}
	return ParsePublicKeyUncompressed(spki.BitString.Bytes)
}

// ParsePublicKeyBase64 从 Base64 编码的 ASN.1 DER 公钥解析 SM2 公钥。
// 招商银行等网关以此形式下发平台公钥。
func ParsePublicKeyBase64(b64 string) (*PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("sm2: 公钥 Base64 解析失败: " + err.Error())
	}
	return ParsePublicKeyDER(der)
}

// ParsePublicKeyUncompressed 从非压缩点格式（0x04 || X || Y，共 65 字节）解析公钥，
// 并校验该点位于曲线上。自行实现以避免调用已弃用的 elliptic.Unmarshal。
func ParsePublicKeyUncompressed(point []byte) (*PublicKey, error) {
	if len(point) != 65 || point[0] != 0x04 {
		return nil, errors.New("sm2: 公钥点格式非法，应为 65 字节非压缩格式（0x04 前缀）")
	}
	pub := &PublicKey{
		Curve: sm2Curve,
		X:     new(big.Int).SetBytes(point[1:33]),
		Y:     new(big.Int).SetBytes(point[33:]),
	}
	if err := CheckPublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// MarshalPublicKeyUncompressed 将公钥编码为非压缩点格式（0x04 || X || Y）。
func MarshalPublicKeyUncompressed(pub *PublicKey) []byte {
	out := make([]byte, 0, 65)
	out = append(out, 0x04)
	out = append(out, pad32(pub.X.Bytes())...)
	out = append(out, pad32(pub.Y.Bytes())...)
	return out
}

// MarshalPublicKeyDER 将公钥编码为 ASN.1 DER 的 SubjectPublicKeyInfo 结构。
func MarshalPublicKeyDER(pub *PublicKey) ([]byte, error) {
	if err := CheckPublicKey(pub); err != nil {
		return nil, err
	}
	paramBytes, err := asn1.Marshal(oidNamedCurveSM2)
	if err != nil {
		return nil, err
	}
	var spki pkixPublicKey
	spki.Algo.Algorithm = oidSM2
	spki.Algo.Parameters = asn1.RawValue{FullBytes: paramBytes}
	point := MarshalPublicKeyUncompressed(pub)
	spki.BitString = asn1.BitString{Bytes: point, BitLength: len(point) * 8}
	return asn1.Marshal(spki)
}

// MarshalPublicKeyBase64 将公钥编码为 Base64 的 ASN.1 DER 公钥。
func MarshalPublicKeyBase64(pub *PublicKey) (string, error) {
	der, err := MarshalPublicKeyDER(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// encodeHexRS 将签名分量编码为 r||s 的 64 字节小写 HEX。
func encodeHexRS(r, s *big.Int) string {
	out := make([]byte, 0, 64)
	out = append(out, pad32(r.Bytes())...)
	out = append(out, pad32(s.Bytes())...)
	return hex.EncodeToString(out)
}

// decodeHexRS 解析 r||s 的 64 字节 HEX 签名。
func decodeHexRS(sigHex string) (r, s *big.Int, err error) {
	raw, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, nil, errors.New("sm2: 签名 HEX 解析失败: " + err.Error())
	}
	if len(raw) != 64 {
		return nil, nil, fmt.Errorf("sm2: r||s 签名长度应为 64 字节，实际 %d 字节", len(raw))
	}
	return new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]), nil
}
