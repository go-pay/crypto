package sm2

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

// signature 是 SM2 签名值 (r, s) 的 ASN.1 结构。
type signature struct {
	R, S *big.Int
}

// Sign 用私钥对 msg 签名，返回 ASN.1 DER 编码的签名值（SEQUENCE{r, s}）。
// uid 传 nil 时使用 DefaultUID。
func Sign(priv *PrivateKey, msg, uid []byte) ([]byte, error) {
	r, s, err := SignToRS(priv, msg, uid)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(signature{r, s})
}

// SignHex 用私钥对 msg 签名，返回 r||s 拼接后的 64 字节 HEX 编码签名值。
// 部分银行网关（如招商银行对账文件接口）要求这种裸签名格式。
func SignHex(priv *PrivateKey, msg, uid []byte) (string, error) {
	r, s, err := SignToRS(priv, msg, uid)
	if err != nil {
		return "", err
	}
	return encodeHexRS(r, s), nil
}

// SignToRS 用私钥对 msg 签名，返回签名值分量 r、s（GB/T 32918.2-2016 6.1）。
func SignToRS(priv *PrivateKey, msg, uid []byte) (r, s *big.Int, err error) {
	if priv == nil || priv.D == nil {
		return nil, nil, ErrInvalidPrivateKey
	}
	n := sm2Curve.N
	// 私钥有效区间为 [1, n-2]。
	if priv.D.Sign() <= 0 || priv.D.Cmp(new(big.Int).Sub(n, big.NewInt(1))) >= 0 {
		return nil, nil, ErrInvalidPrivateKey
	}
	e, err := digest(&priv.PublicKey, uid, msg)
	if err != nil {
		return nil, nil, err
	}

	one := big.NewInt(1)
	// (1+d)^-1 在整个签名过程中固定，提前计算一次。
	d1Inv := new(big.Int).ModInverse(new(big.Int).Add(priv.D, one), n)
	if d1Inv == nil {
		return nil, nil, ErrInvalidPrivateKey
	}

	for {
		// A3: 用随机数 k ∈ [1, n-1] 计算 (x1, y1) = [k]G
		k, err := randFieldElement(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		x1, _ := sm2Curve.ScalarBaseMult(k.Bytes())

		// A4: r = (e + x1) mod n，要求 r ≠ 0 且 r + k ≠ n
		r = new(big.Int).Add(e, x1)
		r.Mod(r, n)
		if r.Sign() == 0 || new(big.Int).Add(r, k).Cmp(n) == 0 {
			continue
		}

		// A5: s = ((1+d)^-1 · (k - r·d)) mod n，要求 s ≠ 0
		s = new(big.Int).Mul(r, priv.D)
		s.Sub(k, s)
		s.Mul(s, d1Inv)
		s.Mod(s, n)
		if s.Sign() == 0 {
			continue
		}
		return r, s, nil
	}
}

// Verify 用公钥校验 ASN.1 DER 编码的签名值。验签通过返回 nil。
// uid 传 nil 时使用 DefaultUID。
func Verify(pub *PublicKey, msg, sig, uid []byte) error {
	var sg signature
	rest, err := asn1.Unmarshal(sig, &sg)
	if err != nil {
		return errors.New("sm2: 签名 ASN.1 解析失败: " + err.Error())
	}
	if len(rest) != 0 {
		return errors.New("sm2: 签名 ASN.1 存在多余数据")
	}
	return VerifyRS(pub, msg, sg.R, sg.S, uid)
}

// VerifyHex 用公钥校验 r||s 拼接的 64 字节 HEX 编码签名值。
func VerifyHex(pub *PublicKey, msg []byte, sigHex string, uid []byte) error {
	r, s, err := decodeHexRS(sigHex)
	if err != nil {
		return err
	}
	return VerifyRS(pub, msg, r, s, uid)
}

// VerifyRS 用公钥校验签名分量 r、s（GB/T 32918.2-2016 7.1）。
func VerifyRS(pub *PublicKey, msg []byte, r, s *big.Int, uid []byte) error {
	if err := CheckPublicKey(pub); err != nil {
		return err
	}
	if r == nil || s == nil {
		return ErrVerifyFailed
	}
	n := sm2Curve.N
	one := big.NewInt(1)
	// B1、B2: r、s ∈ [1, n-1]
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return ErrVerifyFailed
	}
	// B5: t = (r + s) mod n，t ≠ 0
	t := new(big.Int).Add(r, s)
	t.Mod(t, n)
	if t.Sign() == 0 {
		return ErrVerifyFailed
	}
	// B4: e = SM3(Z_A || M)
	e, err := digest(pub, uid, msg)
	if err != nil {
		return err
	}
	// B6: (x1, y1) = [s]G + [t]P_A
	x1, y1 := sm2Curve.ScalarBaseMult(s.Bytes())
	x2, y2 := sm2Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ := sm2Curve.Add(x1, y1, x2, y2)
	// B7: R = (e + x1) mod n，校验 R == r
	rv := new(big.Int).Add(e, x)
	rv.Mod(rv, n)
	if rv.Cmp(r) != 0 {
		return ErrVerifyFailed
	}
	return nil
}

// randFieldElement 生成区间 [1, n-1] 内的随机数。
func randFieldElement(random io.Reader) (*big.Int, error) {
	if random == nil {
		random = rand.Reader
	}
	one := big.NewInt(1)
	// rand.Int 返回 [0, max)，取 max = n-1 后加 1 得到 [1, n-1]。
	max := new(big.Int).Sub(sm2Curve.N, one)
	k, err := rand.Int(random, max)
	if err != nil {
		return nil, err
	}
	return k.Add(k, one), nil
}
