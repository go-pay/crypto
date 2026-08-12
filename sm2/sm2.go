// Package sm2 实现国密 SM2 椭圆曲线公钥密码算法（GB/T 32918 系列）。
//
// 提供数字签名（GB/T 32918.2）与公钥加密（GB/T 32918.4），签名摘要算法为
// SM3，默认用户标识为国密推荐值 "1234567812345678"。
//
// 曲线运算基于标准库 crypto/elliptic 的通用实现（SM2 推荐曲线参数见
// GB/T 32918.5）。该通用实现不是常数时间的，在需要抵御本地时序侧信道的
// 场景下应改用带常数时间实现的库；对于服务端调用银行/支付网关接口的
// 典型用法，这一取舍换来的是零外部依赖与可完整审计的代码量。
package sm2

import (
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/go-pay/crypto/sm3"
)

// DefaultUID 国密推荐的默认用户标识 ID_A（GB/T 32918.2 附录 A）。
// 招商银行、多数银行网关均使用该默认值。
var DefaultUID = []byte("1234567812345678")

// sm2Curve 缓存 SM2 推荐曲线。
var sm2Curve = newSM2Curve()

// newSM2Curve 构造 SM2 推荐曲线参数（GB/T 32918.5-2017 第 1 章）。
//
//	p  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
//	a  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC （即 p-3）
//	b  = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
//	n  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
//	Gx = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
//	Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
//
// 注意 a = p-3，正好符合 elliptic.CurveParams 对 a 的隐含约定，因此可直接复用
// 标准库的点运算实现。
func newSM2Curve() *elliptic.CurveParams {
	c := &elliptic.CurveParams{Name: "SM2-P-256", BitSize: 256}
	c.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	c.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	c.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	c.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	c.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	return c
}

// P256 返回 SM2 推荐椭圆曲线。
func P256() elliptic.Curve { return sm2Curve }

// paramA 返回曲线方程中的系数 a（等于 p-3）。
func paramA() *big.Int {
	return new(big.Int).Sub(sm2Curve.P, big.NewInt(3))
}

// PublicKey 是 SM2 公钥。
type PublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

// PrivateKey 是 SM2 私钥。
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// Public 返回对应的公钥。
func (priv *PrivateKey) Public() *PublicKey { return &priv.PublicKey }

var (
	// ErrInvalidPrivateKey 私钥不在有效区间 [1, n-2] 内。
	ErrInvalidPrivateKey = errors.New("sm2: 私钥不在有效区间内")
	// ErrInvalidPublicKey 公钥不是曲线上的有效点。
	ErrInvalidPublicKey = errors.New("sm2: 公钥不是曲线上的有效点")
	// ErrVerifyFailed 签名验证不通过。
	ErrVerifyFailed = errors.New("sm2: 验签失败")
	// ErrInvalidCipher 密文格式非法或已损坏。
	ErrInvalidCipher = errors.New("sm2: 密文格式非法")
)

// pad32 将大整数的字节表示左补零至 32 字节（SM2 域元素固定长度）。
func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// isOnCurve 校验点 (x, y) 是否满足 y² = x³ + ax + b (mod p)，
// 并排除无穷远点与超出域范围的坐标。自行实现以避免调用已弃用的
// elliptic.Curve.IsOnCurve。
func isOnCurve(x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	p := sm2Curve.P
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return false
	}
	// 排除无穷远点在仿射坐标下的表示 (0, 0)。
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	// 左边：y² mod p
	left := new(big.Int).Mul(y, y)
	left.Mod(left, p)
	// 右边：x³ + ax + b mod p
	right := new(big.Int).Mul(x, x)
	right.Mul(right, x)
	ax := new(big.Int).Mul(paramA(), x)
	right.Add(right, ax)
	right.Add(right, sm2Curve.B)
	right.Mod(right, p)
	return left.Cmp(right) == 0
}

// CheckPublicKey 校验公钥是否为曲线上的有效点。
func CheckPublicKey(pub *PublicKey) error {
	if pub == nil || !isOnCurve(pub.X, pub.Y) {
		return ErrInvalidPublicKey
	}
	return nil
}

// za 计算 Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)
// （GB/T 32918.2-2016 5.5）。
func za(pub *PublicKey, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = DefaultUID
	}
	// ENTL 为 ID 的比特长度，占 2 字节，因此 ID 长度上限为 8191 字节。
	if len(uid) >= 1<<13 {
		return nil, errors.New("sm2: 用户标识 ID 过长")
	}
	entl := uint16(8 * len(uid))
	h := sm3.New()
	_, _ = h.Write([]byte{byte(entl >> 8), byte(entl)})
	_, _ = h.Write(uid)
	_, _ = h.Write(pad32(paramA().Bytes()))
	_, _ = h.Write(pad32(sm2Curve.B.Bytes()))
	_, _ = h.Write(pad32(sm2Curve.Gx.Bytes()))
	_, _ = h.Write(pad32(sm2Curve.Gy.Bytes()))
	_, _ = h.Write(pad32(pub.X.Bytes()))
	_, _ = h.Write(pad32(pub.Y.Bytes()))
	return h.Sum(nil), nil
}

// digest 计算待签名摘要 e = SM3(Z_A || M)（GB/T 32918.2-2016 6.1 A1~A2）。
func digest(pub *PublicKey, uid, msg []byte) (*big.Int, error) {
	z, err := za(pub, uid)
	if err != nil {
		return nil, err
	}
	h := sm3.New()
	_, _ = h.Write(z)
	_, _ = h.Write(msg)
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

// kdf 密钥派生函数（GB/T 32918.4-2016 5.4.3）：
// 以 SM3 为杂凑函数，对 z 反复计数杂凑生成 klen 字节密钥流。
// 返回值第二项报告密钥流是否全为零（此时调用方需重新选取随机数）。
func kdf(klen int, z ...[]byte) ([]byte, bool) {
	out := make([]byte, 0, klen)
	var ctBuf [4]byte
	h := sm3.New()
	for ct := uint32(1); len(out) < klen; ct++ {
		h.Reset()
		for _, zz := range z {
			_, _ = h.Write(zz)
		}
		binary.BigEndian.PutUint32(ctBuf[:], ct)
		_, _ = h.Write(ctBuf[:])
		out = h.Sum(out)
	}
	out = out[:klen]
	for _, b := range out {
		if b != 0 {
			return out, true
		}
	}
	return out, false
}
