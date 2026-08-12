package sm2

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// 跨实现已知答案向量（KAT）。
//
// 下列 pubBase64 / sigDER / cipherDER 均由 tjfoc/gmsm v1.4.1 生成，用于锁定
// 本实现与 gmsm（即招商银行等网关联调验证过的实现）的字节级兼容性。
// 私钥取自国密标准示例值，仅用于测试。
const (
	privHex   = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
	pubBase64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAECfnfMR5UIaFQ3X0WHkvFxnIXn60YM/wHa7CP81bzUCDM6kkM4md1pS3G6nGMwapgCu0F+/NeCEpmMvYHLamtEw=="
	pubXHex   = "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
	pubYHex   = "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
	message   = "message digest"

	// gmsm priv.Sign(rand, []byte(message), nil) 的输出，ASN.1 DER 编码。
	gmsmSigDER = "304402203d72aed265584d819a1dcf7cc4fe1bb2451659a5849b04bcc1fe8223f493baa802204be68eda55e43f4546d58bb63b99ab4302acc4167f4338429b96f2eab35017dd"
	// gmsm sm2.EncryptAsn1(pub, []byte(cipherPlain), rand) 的输出。
	gmsmCipherDER = "30780220719f46b296d5fcd6939ad85e7c592c1a292830791bf4439e5db44e9fe1bcf11a02202208e8dc7995914b5b0cbd4ec75e2d4e021231a0eb84842bb536ae39303e5eb904200f2564dc93900f931608c4c67e61d7a0fa04bb3a7ed584a6bb1bcfccfad475730410b140e0df840ebf36d420feb61c4db1db"
	cipherPlain   = "0123456789abcdef"
)

func mustPriv(t *testing.T) *PrivateKey {
	t.Helper()
	priv, err := ParsePrivateKeyHex(privHex)
	if err != nil {
		t.Fatalf("ParsePrivateKeyHex 失败: %v", err)
	}
	return priv
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("HEX 解析失败: %v", err)
	}
	return b
}

// TestCurveParams 校验曲线参数与 GB/T 32918.5-2017 一致，且 a = p-3。
func TestCurveParams(t *testing.T) {
	c := sm2Curve
	if !isOnCurve(c.Gx, c.Gy) {
		t.Error("isOnCurve 判定基点 G 不在曲线上")
	}
	// a 必须等于 p-3，否则不能复用标准库通用点运算。
	wantA := new(big.Int).Sub(c.P, big.NewInt(3))
	if paramA().Cmp(wantA) != 0 {
		t.Error("曲线系数 a 不等于 p-3")
	}
	// [n]G 应为无穷远点，标准库以 (0, 0) 表示。
	x, y := c.ScalarBaseMult(c.N.Bytes())
	if x.Sign() != 0 || y.Sign() != 0 {
		t.Errorf("[n]G = (%x, %x)，期望无穷远点", x, y)
	}
	if P256() != sm2Curve {
		t.Error("P256() 未返回 SM2 曲线")
	}
}

// TestPrivateKeyDerivesPublicKey 私钥解析后应推导出正确公钥。
func TestPrivateKeyDerivesPublicKey(t *testing.T) {
	priv := mustPriv(t)
	if got := hex.EncodeToString(pad32(priv.X.Bytes())); got != pubXHex {
		t.Errorf("公钥 X = %s, 期望 %s", got, pubXHex)
	}
	if got := hex.EncodeToString(pad32(priv.Y.Bytes())); got != pubYHex {
		t.Errorf("公钥 Y = %s, 期望 %s", got, pubYHex)
	}
	if err := CheckPublicKey(priv.Public()); err != nil {
		t.Errorf("推导出的公钥校验失败: %v", err)
	}
	if got := MarshalPrivateKeyHex(priv); !strings.EqualFold(got, privHex) {
		t.Errorf("MarshalPrivateKeyHex = %s, 期望 %s", got, privHex)
	}
}

// TestPublicKeyBase64KAT 解析 gmsm 生成的 Base64 公钥，坐标须完全一致。
func TestPublicKeyBase64KAT(t *testing.T) {
	pub, err := ParsePublicKeyBase64(pubBase64)
	if err != nil {
		t.Fatalf("ParsePublicKeyBase64 失败: %v", err)
	}
	if got := hex.EncodeToString(pad32(pub.X.Bytes())); got != pubXHex {
		t.Errorf("X = %s, 期望 %s", got, pubXHex)
	}
	if got := hex.EncodeToString(pad32(pub.Y.Bytes())); got != pubYHex {
		t.Errorf("Y = %s, 期望 %s", got, pubYHex)
	}
	// 反向编码必须还原出同一段 Base64，保证与 gmsm 的 DER 字节级一致。
	back, err := MarshalPublicKeyBase64(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKeyBase64 失败: %v", err)
	}
	if back != pubBase64 {
		t.Errorf("公钥 DER 往返不一致\n got: %s\nwant: %s", back, pubBase64)
	}
}

// TestVerifyGmsmSignatureKAT 验签 gmsm 生成的签名，证明摘要（Z_A）与验签算法一致。
func TestVerifyGmsmSignatureKAT(t *testing.T) {
	pub, err := ParsePublicKeyBase64(pubBase64)
	if err != nil {
		t.Fatalf("ParsePublicKeyBase64 失败: %v", err)
	}
	sig := mustHex(t, gmsmSigDER)
	if err = Verify(pub, []byte(message), sig, nil); err != nil {
		t.Errorf("验签 gmsm 签名失败: %v", err)
	}
	// 显式传入国密默认 UID，结果应相同。
	if err = Verify(pub, []byte(message), sig, DefaultUID); err != nil {
		t.Errorf("显式传 DefaultUID 验签失败: %v", err)
	}
	// 篡改消息、篡改签名、换 UID 都必须验签失败。
	if err = Verify(pub, []byte(message+"!"), sig, nil); err == nil {
		t.Error("消息被篡改时验签应失败")
	}
	if err = Verify(pub, []byte(message), sig, []byte("8765432187654321")); err == nil {
		t.Error("UID 不匹配时验签应失败")
	}
	bad := bytes.Clone(sig)
	bad[len(bad)-1] ^= 0xff
	if err = Verify(pub, []byte(message), bad, nil); err == nil {
		t.Error("签名被篡改时验签应失败")
	}
}

// TestDecryptGmsmCipherKAT 解密 gmsm 生成的密文，证明 KDF、C3 与 ASN.1 编码一致。
func TestDecryptGmsmCipherKAT(t *testing.T) {
	priv := mustPriv(t)
	got, err := Decrypt(priv, mustHex(t, gmsmCipherDER))
	if err != nil {
		t.Fatalf("解密 gmsm 密文失败: %v", err)
	}
	if string(got) != cipherPlain {
		t.Errorf("解密结果 = %q, 期望 %q", got, cipherPlain)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := mustPriv(t)
	msgs := [][]byte{
		nil,
		[]byte(""),
		[]byte("a"),
		[]byte(message),
		[]byte("appid=123&biz_content={\"a\":1}&timestamp=20250813000000"),
		bytes.Repeat([]byte("x"), 10000),
	}
	uids := [][]byte{nil, DefaultUID, []byte("merchant-001")}
	for _, msg := range msgs {
		for _, uid := range uids {
			sig, err := Sign(priv, msg, uid)
			if err != nil {
				t.Fatalf("Sign 失败: %v", err)
			}
			if err = Verify(priv.Public(), msg, sig, uid); err != nil {
				t.Errorf("Verify(len=%d, uid=%q) 失败: %v", len(msg), uid, err)
			}
		}
	}
}

// TestSignRandomized 相同消息两次签名应不同（k 随机），但都能验证通过。
func TestSignRandomized(t *testing.T) {
	priv := mustPriv(t)
	a, err := Sign(priv, []byte(message), nil)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}
	b, err := Sign(priv, []byte(message), nil)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("两次签名结果相同，随机数 k 可能未生效")
	}
	if err = Verify(priv.Public(), []byte(message), b, nil); err != nil {
		t.Errorf("第二次签名验签失败: %v", err)
	}
}

func TestSignHexRoundTrip(t *testing.T) {
	priv := mustPriv(t)
	sigHex, err := SignHex(priv, []byte(message), nil)
	if err != nil {
		t.Fatalf("SignHex 失败: %v", err)
	}
	// r||s 各 32 字节，HEX 后固定 128 字符，招行对账接口依赖该长度。
	if len(sigHex) != 128 {
		t.Errorf("SignHex 长度 = %d, 期望 128", len(sigHex))
	}
	if sigHex != strings.ToLower(sigHex) {
		t.Error("SignHex 应输出小写 HEX")
	}
	if err = VerifyHex(priv.Public(), []byte(message), sigHex, nil); err != nil {
		t.Errorf("VerifyHex 失败: %v", err)
	}
	// DER 与 r||s 两种编码可互换验签。
	r, s, err := decodeHexRS(sigHex)
	if err != nil {
		t.Fatalf("decodeHexRS 失败: %v", err)
	}
	if err = VerifyRS(priv.Public(), []byte(message), r, s, nil); err != nil {
		t.Errorf("VerifyRS 失败: %v", err)
	}
	if encodeHexRS(r, s) != sigHex {
		t.Error("encodeHexRS/decodeHexRS 往返不一致")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	priv := mustPriv(t)
	cases := [][]byte{
		[]byte("a"),
		[]byte(cipherPlain),
		bytes.Repeat([]byte{0x00}, 16), // 全零明文
		bytes.Repeat([]byte("m"), 1000),
	}
	for _, plain := range cases {
		ct, err := Encrypt(priv.Public(), plain)
		if err != nil {
			t.Fatalf("Encrypt(len=%d) 失败: %v", len(plain), err)
		}
		got, err := Decrypt(priv, ct)
		if err != nil {
			t.Fatalf("Decrypt(len=%d) 失败: %v", len(plain), err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("加解密往返不一致，len=%d", len(plain))
		}
		// 篡改 C2 必须被 C3 校验拦住。
		bad := bytes.Clone(ct)
		bad[len(bad)-1] ^= 0xff
		if _, err = Decrypt(priv, bad); err == nil {
			t.Error("密文被篡改时解密应失败")
		}
	}
}

func TestEncryptC1C3C2RoundTrip(t *testing.T) {
	priv := mustPriv(t)
	plain := []byte(cipherPlain)
	ct, err := EncryptC1C3C2(priv.Public(), plain)
	if err != nil {
		t.Fatalf("EncryptC1C3C2 失败: %v", err)
	}
	if len(ct) != 1+64+32+len(plain) || ct[0] != 0x04 {
		t.Errorf("C1C3C2 密文长度 = %d，首字节 = %#x", len(ct), ct[0])
	}
	got, err := DecryptC1C3C2(priv, ct)
	if err != nil {
		t.Fatalf("DecryptC1C3C2 失败: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("C1C3C2 往返 = %q, 期望 %q", got, plain)
	}
	for _, bad := range [][]byte{nil, {0x04}, make([]byte, 97), append([]byte{0x03}, make([]byte, 200)...)} {
		if _, err = DecryptC1C3C2(priv, bad); err == nil {
			t.Errorf("非法 C1C3C2 密文（len=%d）应返回错误", len(bad))
		}
	}
}

func TestGenerateKey(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 5; i++ {
		priv, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey 失败: %v", err)
		}
		if err = CheckPublicKey(priv.Public()); err != nil {
			t.Fatalf("生成的公钥非法: %v", err)
		}
		h := MarshalPrivateKeyHex(priv)
		if len(h) != 64 {
			t.Errorf("私钥 HEX 长度 = %d, 期望 64", len(h))
		}
		if seen[h] {
			t.Fatal("GenerateKey 生成了重复私钥")
		}
		seen[h] = true

		sig, err := Sign(priv, []byte(message), nil)
		if err != nil {
			t.Fatalf("Sign 失败: %v", err)
		}
		if err = Verify(priv.Public(), []byte(message), sig, nil); err != nil {
			t.Errorf("新生成密钥验签失败: %v", err)
		}
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	n := sm2Curve.N
	tests := []struct {
		name string
		hex  string
	}{
		{"非 HEX", "zz"},
		{"长度不足", "3945208F"},
		{"长度超出", privHex + "00"},
		{"私钥为 0", strings.Repeat("0", 64)},
		{"私钥为 n-1（超出 [1, n-2]）", hex.EncodeToString(pad32(new(big.Int).Sub(n, big.NewInt(1)).Bytes()))},
		{"私钥为 n", hex.EncodeToString(pad32(n.Bytes()))},
	}
	for _, tt := range tests {
		if _, err := ParsePrivateKeyHex(tt.hex); err == nil {
			t.Errorf("%s: 应返回错误", tt.name)
		}
	}
	if _, err := ParsePrivateKeyBytes(make([]byte, 31)); err == nil {
		t.Error("31 字节私钥应返回错误")
	}
}

func TestParsePublicKeyInvalid(t *testing.T) {
	if _, err := ParsePublicKeyBase64("not-base64!!"); err == nil {
		t.Error("非法 Base64 应返回错误")
	}
	if _, err := ParsePublicKeyDER([]byte{0x30, 0x01}); err == nil {
		t.Error("非法 DER 应返回错误")
	}
	// DER 尾部追加多余字节必须被拒绝，避免签名/公钥可延展。
	der, err := base64.StdEncoding.DecodeString(pubBase64)
	if err != nil {
		t.Fatalf("Base64 解析失败: %v", err)
	}
	if _, err = ParsePublicKeyDER(append(bytes.Clone(der), 0x00)); err == nil {
		t.Error("DER 尾部多余数据应返回错误")
	}
	// 非压缩点格式校验。
	if _, err = ParsePublicKeyUncompressed(make([]byte, 65)); err == nil {
		t.Error("首字节非 0x04 应返回错误")
	}
	if _, err = ParsePublicKeyUncompressed(make([]byte, 64)); err == nil {
		t.Error("长度非 65 应返回错误")
	}
	// 曲线外的点必须被拒绝，防止无效曲线攻击。
	notOnCurve := make([]byte, 65)
	notOnCurve[0] = 0x04
	notOnCurve[64] = 0x01
	if _, err = ParsePublicKeyUncompressed(notOnCurve); err == nil {
		t.Error("曲线外的点应返回错误")
	}
}

func TestMarshalPublicKeyUncompressed(t *testing.T) {
	priv := mustPriv(t)
	point := MarshalPublicKeyUncompressed(priv.Public())
	if len(point) != 65 || point[0] != 0x04 {
		t.Fatalf("非压缩点长度 = %d，首字节 = %#x", len(point), point[0])
	}
	pub, err := ParsePublicKeyUncompressed(point)
	if err != nil {
		t.Fatalf("ParsePublicKeyUncompressed 失败: %v", err)
	}
	if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
		t.Error("非压缩点往返后坐标不一致")
	}
}

func TestIsOnCurveRejectsSpecialPoints(t *testing.T) {
	zero := big.NewInt(0)
	if isOnCurve(nil, zero) || isOnCurve(zero, nil) {
		t.Error("nil 坐标应判定为非法")
	}
	if isOnCurve(zero, zero) {
		t.Error("无穷远点 (0,0) 应判定为非法")
	}
	if isOnCurve(sm2Curve.P, sm2Curve.Gy) {
		t.Error("坐标等于 p 应判定为非法（超出域范围）")
	}
	if isOnCurve(new(big.Int).Neg(sm2Curve.Gx), sm2Curve.Gy) {
		t.Error("负坐标应判定为非法")
	}
}

func TestVerifyRejectsOutOfRangeRS(t *testing.T) {
	priv := mustPriv(t)
	n := sm2Curve.N
	tests := []struct {
		name string
		r, s *big.Int
	}{
		{"r 为 nil", nil, big.NewInt(1)},
		{"s 为 nil", big.NewInt(1), nil},
		{"r 为 0", big.NewInt(0), big.NewInt(1)},
		{"s 为 0", big.NewInt(1), big.NewInt(0)},
		{"r 等于 n", n, big.NewInt(1)},
		{"s 等于 n", big.NewInt(1), n},
		{"r+s 等于 n", big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1))},
	}
	for _, tt := range tests {
		if err := VerifyRS(priv.Public(), []byte(message), tt.r, tt.s, nil); err == nil {
			t.Errorf("%s: 应验签失败", tt.name)
		}
	}
}

func TestSignNilPrivateKey(t *testing.T) {
	if _, err := Sign(nil, []byte(message), nil); err == nil {
		t.Error("私钥为 nil 时应返回错误")
	}
	if _, _, err := SignToRS(&PrivateKey{}, []byte(message), nil); err == nil {
		t.Error("私钥 D 为 nil 时应返回错误")
	}
	if _, err := Decrypt(nil, mustHex(t, gmsmCipherDER)); err == nil {
		t.Error("私钥为 nil 时解密应返回错误")
	}
	if err := Verify(nil, []byte(message), mustHex(t, gmsmSigDER), nil); err == nil {
		t.Error("公钥为 nil 时验签应返回错误")
	}
	if _, err := Encrypt(nil, []byte("x")); err == nil {
		t.Error("公钥为 nil 时加密应返回错误")
	}
}

func TestEncryptRejectsEmptyPlain(t *testing.T) {
	priv := mustPriv(t)
	if _, err := Encrypt(priv.Public(), nil); err == nil {
		t.Error("空明文加密应返回错误")
	}
}

func TestDecryptRejectsMalformed(t *testing.T) {
	priv := mustPriv(t)
	valid := mustHex(t, gmsmCipherDER)
	if _, err := Decrypt(priv, append(bytes.Clone(valid), 0x00)); err == nil {
		t.Error("密文尾部多余数据应返回错误")
	}
	if _, err := Decrypt(priv, []byte{0x30, 0x00}); err == nil {
		t.Error("空 SEQUENCE 密文应返回错误")
	}
	if _, err := Decrypt(priv, nil); err == nil {
		t.Error("空密文应返回错误")
	}
}

// TestZALongUID ENTL 只有 2 字节，ID 长度上限为 8191 字节。
func TestZALongUID(t *testing.T) {
	priv := mustPriv(t)
	if _, err := za(priv.Public(), bytes.Repeat([]byte("a"), 8192)); err == nil {
		t.Error("超长 UID 应返回错误")
	}
	if _, err := za(priv.Public(), bytes.Repeat([]byte("a"), 8191)); err != nil {
		t.Errorf("8191 字节 UID 应可用: %v", err)
	}
}

// TestKDF 校验密钥派生函数的长度、确定性与跨分组连续性。
func TestKDF(t *testing.T) {
	z := []byte("shared-secret")
	for _, klen := range []int{1, 31, 32, 33, 64, 100} {
		out, ok := kdf(klen, z)
		if !ok {
			t.Fatalf("klen=%d: kdf 返回全零", klen)
		}
		if len(out) != klen {
			t.Errorf("klen=%d: 输出长度 = %d", klen, len(out))
		}
		// 同一输入必须得到同一输出。
		again, _ := kdf(klen, z)
		if !bytes.Equal(out, again) {
			t.Errorf("klen=%d: kdf 输出不确定", klen)
		}
		// 更长的输出必须以更短的输出为前缀（计数器构造的性质）。
		long, _ := kdf(klen+40, z)
		if !bytes.Equal(long[:klen], out) {
			t.Errorf("klen=%d: 长输出未以短输出为前缀", klen)
		}
	}
	// 多段输入等价于其拼接。
	a, _ := kdf(48, []byte("abc"), []byte("def"))
	b, _ := kdf(48, []byte("abcdef"))
	if !bytes.Equal(a, b) {
		t.Error("kdf 多段输入与拼接输入结果不一致")
	}
}

func TestPad32(t *testing.T) {
	if got := pad32(nil); len(got) != 32 || got[31] != 0 {
		t.Error("pad32(nil) 应返回 32 字节全零")
	}
	if got := pad32([]byte{0x01}); len(got) != 32 || got[31] != 0x01 {
		t.Error("pad32 应左补零")
	}
	in := bytes.Repeat([]byte{0xff}, 40)
	if got := pad32(in); len(got) != 32 {
		t.Errorf("pad32 超长输入应截取低 32 字节，得到 %d 字节", len(got))
	}
}

func BenchmarkSign(b *testing.B) {
	priv, err := ParsePrivateKeyHex(privHex)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte(message)
	for i := 0; i < b.N; i++ {
		if _, err = Sign(priv, msg, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	priv, err := ParsePrivateKeyHex(privHex)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte(message)
	sig, err := Sign(priv, msg, nil)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if err = Verify(priv.Public(), msg, sig, nil); err != nil {
			b.Fatal(err)
		}
	}
}
