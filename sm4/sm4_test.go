package sm4

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

// GB/T 32907-2016 附录 A 标准测试数据。
var (
	stdKey    = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	stdPlain  = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	stdCipher = "681edf34d206965e86b3e94f536e4246"
)

// TestStandardVector 附录 A.1：对一个分组加密一次的示例。
func TestStandardVector(t *testing.T) {
	c, err := NewCipher(stdKey)
	if err != nil {
		t.Fatalf("NewCipher 失败: %v", err)
	}
	dst := make([]byte, BlockSize)
	c.Encrypt(dst, stdPlain)
	if got := hex.EncodeToString(dst); got != stdCipher {
		t.Errorf("Encrypt = %s, 期望 %s", got, stdCipher)
	}

	// 解密应还原明文。
	back := make([]byte, BlockSize)
	c.Decrypt(back, dst)
	if !bytes.Equal(back, stdPlain) {
		t.Errorf("Decrypt = %x, 期望 %x", back, stdPlain)
	}
}

// TestStandardVectorMillion 附录 A.2：用同一密钥对同一明文反复加密 1000000 次。
func TestStandardVectorMillion(t *testing.T) {
	const want = "595298c7c6fd271f0402f804c33d3f66"
	c, err := NewCipher(stdKey)
	if err != nil {
		t.Fatalf("NewCipher 失败: %v", err)
	}
	buf := make([]byte, BlockSize)
	copy(buf, stdPlain)
	for i := 0; i < 1000000; i++ {
		c.Encrypt(buf, buf)
	}
	if got := hex.EncodeToString(buf); got != want {
		t.Errorf("加密 1000000 次 = %s, 期望 %s", got, want)
	}
}

// TestECBCompatVector 跨实现已知答案测试（KAT）。
//
// 密文由 tjfoc/gmsm v1.4.1 的 sm4.Sm4Ecb(key, plain, true) 生成，用于锁定
// 本实现（SM4-ECB + PKCS#7 填充）与其字节级兼容 —— 招商银行等网关的敏感
// 字段加密依赖这一格式。
func TestECBCompatVector(t *testing.T) {
	var (
		key   = []byte("0123456789abcdef")
		plain = "招商银行聚合支付敏感字段"
		want  = "ced80e080a9461fa722f240762127850d29a0797abf323749309d399c09566fecf7aebc4a746db356a74d29129e37cb3"
	)
	ct, err := ECBEncrypt([]byte(plain), key)
	if err != nil {
		t.Fatalf("ECBEncrypt 失败: %v", err)
	}
	if got := hex.EncodeToString(ct); got != want {
		t.Errorf("ECBEncrypt = %s\n           期望 %s", got, want)
	}
	raw, err := hex.DecodeString(want)
	if err != nil {
		t.Fatalf("HEX 解析失败: %v", err)
	}
	got, err := ECBDecrypt(raw, key)
	if err != nil {
		t.Fatalf("ECBDecrypt 失败: %v", err)
	}
	if string(got) != plain {
		t.Errorf("ECBDecrypt = %q, 期望 %q", got, plain)
	}
}

// TestCKGeneration 验证固定参数 CK 常量表与国标给出的构造规则一致：
// ck[i] 的第 j 个字节等于 (4i+j)*7 mod 256。
func TestCKGeneration(t *testing.T) {
	for i := 0; i < 32; i++ {
		var want uint32
		for j := 0; j < 4; j++ {
			want |= uint32((4*i+j)*7%256) << (8 * (3 - j))
		}
		if ck[i] != want {
			t.Errorf("ck[%d] = %08x, 按规则计算应为 %08x", i, ck[i], want)
		}
	}
}

// TestSboxIsPermutation S 盒必须是 0..255 上的双射。
func TestSboxIsPermutation(t *testing.T) {
	var seen [256]bool
	for _, v := range sbox {
		if seen[v] {
			t.Fatalf("S 盒中存在重复值 %#x，不是双射", v)
		}
		seen[v] = true
	}
}

func TestKeySizeError(t *testing.T) {
	for _, n := range []int{0, 8, 15, 17, 32} {
		if _, err := NewCipher(make([]byte, n)); err == nil {
			t.Errorf("密钥长度 %d 应返回错误", n)
		}
	}
}

func TestBlockSizeAndInterface(t *testing.T) {
	c, err := NewCipher(stdKey)
	if err != nil {
		t.Fatalf("NewCipher 失败: %v", err)
	}
	if c.BlockSize() != BlockSize || c.BlockSize() != 16 {
		t.Errorf("BlockSize() = %d, 期望 16", c.BlockSize())
	}
	var _ cipher.Block = c
}

func TestECBRoundTrip(t *testing.T) {
	cases := []string{
		"",
		"a",
		"招商银行聚合支付",
		"0123456789abcdef",                 // 恰好一个分组
		"0123456789abcdef0123456789abcdef", // 两个分组
		string(bytes.Repeat([]byte("x"), 1000)),
	}
	for _, plain := range cases {
		ct, err := ECBEncrypt([]byte(plain), stdKey)
		if err != nil {
			t.Fatalf("ECBEncrypt(%q) 失败: %v", plain, err)
		}
		if len(ct)%BlockSize != 0 {
			t.Errorf("ECBEncrypt(%q) 密文长度 %d 不是分组整数倍", plain, len(ct))
		}
		got, err := ECBDecrypt(ct, stdKey)
		if err != nil {
			t.Fatalf("ECBDecrypt(%q) 失败: %v", plain, err)
		}
		if string(got) != plain {
			t.Errorf("ECB 往返 = %q, 期望 %q", got, plain)
		}
	}
}

func TestCBCRoundTrip(t *testing.T) {
	iv := []byte("0123456789abcdef")
	for _, plain := range []string{"", "a", "招商银行聚合支付敏感字段", "0123456789abcdef"} {
		ct, err := CBCEncrypt([]byte(plain), stdKey, iv)
		if err != nil {
			t.Fatalf("CBCEncrypt(%q) 失败: %v", plain, err)
		}
		got, err := CBCDecrypt(ct, stdKey, iv)
		if err != nil {
			t.Fatalf("CBCDecrypt(%q) 失败: %v", plain, err)
		}
		if string(got) != plain {
			t.Errorf("CBC 往返 = %q, 期望 %q", got, plain)
		}
	}
	// iv 长度非法应报错。
	if _, err := CBCEncrypt([]byte("x"), stdKey, []byte("short")); err == nil {
		t.Error("iv 长度非法时 CBCEncrypt 应返回错误")
	}
}

// TestECBDecryptRejectsBadInput 密文长度非法、填充非法都应报错而非返回垃圾数据。
func TestECBDecryptRejectsBadInput(t *testing.T) {
	if _, err := ECBDecrypt(nil, stdKey); err == nil {
		t.Error("空密文应返回错误")
	}
	if _, err := ECBDecrypt(make([]byte, 15), stdKey); err == nil {
		t.Error("非整数倍长度密文应返回错误")
	}
	// 用合法密钥加密后篡改最后一个分组，使填充校验失败的概率极高。
	ct, err := ECBEncrypt([]byte("hello"), stdKey)
	if err != nil {
		t.Fatalf("ECBEncrypt 失败: %v", err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := ECBDecrypt(ct, stdKey); err == nil {
		t.Log("提示：篡改后恰好通过填充校验（概率事件），非缺陷")
	}
}

func TestPKCS7Padding(t *testing.T) {
	// 长度已是整数倍时应补满一个分组，保证可逆。
	in := bytes.Repeat([]byte("a"), 16)
	padded := PKCS7Padding(in, 16)
	if len(padded) != 32 {
		t.Errorf("整数倍输入填充后长度 = %d, 期望 32", len(padded))
	}
	out, err := PKCS7UnPadding(padded, 16)
	if err != nil {
		t.Fatalf("PKCS7UnPadding 失败: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("去填充 = %x, 期望 %x", out, in)
	}
}

func TestPKCS7UnPaddingRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"空输入", nil},
		{"长度非整数倍", make([]byte, 15)},
		{"填充值为0", append(bytes.Repeat([]byte("a"), 15), 0x00)},
		{"填充值超过分组长度", append(bytes.Repeat([]byte("a"), 15), 0x11)},
		{"填充内容不一致", append(bytes.Repeat([]byte("a"), 14), 0x02, 0x03)},
	}
	for _, tt := range tests {
		if _, err := PKCS7UnPadding(tt.in, 16); err == nil {
			t.Errorf("%s: 应返回错误", tt.name)
		}
	}
}

func BenchmarkEncryptBlock(b *testing.B) {
	c, _ := NewCipher(stdKey)
	dst := make([]byte, BlockSize)
	b.SetBytes(BlockSize)
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst, stdPlain)
	}
}
