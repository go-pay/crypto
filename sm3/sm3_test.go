package sm3

import (
	"encoding/hex"
	"hash"
	"strings"
	"testing"
)

// GB/T 32905-2016 附录 A 标准测试向量。
var golden = []struct {
	in  string
	out string
}{
	// 附录 A.1：消息 "abc"
	{"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
	// 附录 A.2：消息 "abcd" 重复 16 次（64 字节，恰好一个分组）
	{strings.Repeat("abcd", 16), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
	// 空消息
	{"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
}

func TestSum(t *testing.T) {
	for i, g := range golden {
		got := Sum([]byte(g.in))
		if hex.EncodeToString(got[:]) != g.out {
			t.Errorf("向量 %d: Sum(%q) = %x, 期望 %s", i, g.in, got, g.out)
		}
	}
}

func TestNewWrite(t *testing.T) {
	for i, g := range golden {
		h := New()
		_, _ = h.Write([]byte(g.in))
		if got := hex.EncodeToString(h.Sum(nil)); got != g.out {
			t.Errorf("向量 %d: New/Write(%q) = %s, 期望 %s", i, g.in, got, g.out)
		}
	}
}

// TestWriteChunked 分多次 Write 应与一次性 Write 结果相同，覆盖跨分组缓冲逻辑。
func TestWriteChunked(t *testing.T) {
	// 构造跨多个分组的长消息，逐一尝试不同的切分点。
	msg := []byte(strings.Repeat("go-pay/crypto SM3 国密杂凑算法测试-", 20))
	want := Sum(msg)
	for split := 0; split <= len(msg); split += 7 {
		h := New()
		_, _ = h.Write(msg[:split])
		_, _ = h.Write(msg[split:])
		if got := h.Sum(nil); hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
			t.Fatalf("切分点 %d: 分次 Write 结果不一致，got %x, want %x", split, got, want)
		}
	}
}

// TestSumDoesNotChangeState 验证 hash.Hash 契约：Sum 不得改变内部状态，
// 多次调用应返回相同结果（tjfoc/gmsm 的实现在此处有缺陷）。
func TestSumDoesNotChangeState(t *testing.T) {
	h := New()
	_, _ = h.Write([]byte("abc"))
	first := hex.EncodeToString(h.Sum(nil))
	second := hex.EncodeToString(h.Sum(nil))
	if first != second {
		t.Errorf("重复调用 Sum 结果不一致: %s != %s", first, second)
	}
	if first != golden[0].out {
		t.Errorf("Sum = %s, 期望 %s", first, golden[0].out)
	}
}

// TestSumAppends 验证 Sum(in) 是把摘要追加在 in 之后，而不是把 in 当作消息写入。
func TestSumAppends(t *testing.T) {
	h := New()
	_, _ = h.Write([]byte("abc"))
	prefix := []byte{0xde, 0xad}
	out := h.Sum(prefix)
	if len(out) != 2+Size {
		t.Fatalf("Sum 返回长度 %d, 期望 %d", len(out), 2+Size)
	}
	if out[0] != 0xde || out[1] != 0xad {
		t.Errorf("Sum 未保留前缀: %x", out[:2])
	}
	if hex.EncodeToString(out[2:]) != golden[0].out {
		t.Errorf("Sum 摘要部分 = %x, 期望 %s", out[2:], golden[0].out)
	}
}

// TestBoundaryLengths 覆盖填充逻辑的边界：分组前后、以及长度模 64 等于 55/56/57 的情况。
func TestBoundaryLengths(t *testing.T) {
	for _, n := range []int{0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 128} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i)
		}
		want := Sum(msg)
		h := New()
		_, _ = h.Write(msg)
		if got := h.Sum(nil); hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
			t.Errorf("长度 %d: Sum 与 New/Write 结果不一致", n)
		}
		if len(want) != Size {
			t.Errorf("长度 %d: 摘要长度 %d, 期望 %d", n, len(want), Size)
		}
	}
}

func TestResetReuse(t *testing.T) {
	h := New()
	_, _ = h.Write([]byte("先写入一些数据污染状态"))
	h.Reset()
	_, _ = h.Write([]byte("abc"))
	if got := hex.EncodeToString(h.Sum(nil)); got != golden[0].out {
		t.Errorf("Reset 后结果 = %s, 期望 %s", got, golden[0].out)
	}
}

func TestSizes(t *testing.T) {
	h := New()
	if h.Size() != Size || h.Size() != 32 {
		t.Errorf("Size() = %d, 期望 32", h.Size())
	}
	if h.BlockSize() != BlockSize || h.BlockSize() != 64 {
		t.Errorf("BlockSize() = %d, 期望 64", h.BlockSize())
	}
	var _ hash.Hash = h
}

func BenchmarkSum1K(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		Sum(data)
	}
}
