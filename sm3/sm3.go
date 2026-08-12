// Package sm3 实现国密 SM3 密码杂凑算法（GB/T 32905-2016）。
//
// 摘要长度 32 字节，分组长度 64 字节，实现 hash.Hash 接口，用法与
// crypto/sha256 一致。
package sm3

import (
	"encoding/binary"
	"hash"
)

// Size SM3 摘要字节长度。
const Size = 32

// BlockSize SM3 分组字节长度。
const BlockSize = 64

// 初始值 IV（GB/T 32905-2016 4.1）。
var iv = [8]uint32{
	0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
	0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
}

// digest 保存 SM3 的中间计算状态。
type digest struct {
	h   [8]uint32       // 迭代压缩值 V
	x   [BlockSize]byte // 未满一个分组的缓冲数据
	nx  int             // x 中的有效字节数
	len uint64          // 已写入的消息总字节数
}

// New 创建一个计算 SM3 摘要的 hash.Hash 实例。
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Sum 返回 data 的 SM3 摘要。
func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	_, _ = d.Write(data)
	return d.checkSum()
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

// Reset 将状态重置为初始值。
func (d *digest) Reset() {
	d.h = iv
	d.nx = 0
	d.len = 0
}

// Write 写入待计算的消息，永不返回错误。
func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	d.len += uint64(n)
	// 先填满缓冲区中已有的不完整分组。
	if d.nx > 0 {
		c := copy(d.x[d.nx:], p)
		d.nx += c
		if d.nx == BlockSize {
			d.block(d.x[:])
			d.nx = 0
		}
		p = p[c:]
	}
	// 处理完整分组。
	if len(p) >= BlockSize {
		nn := len(p) &^ (BlockSize - 1)
		d.block(p[:nn])
		p = p[nn:]
	}
	// 剩余不足一个分组的数据留在缓冲区。
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return n, nil
}

// Sum 将摘要追加到 in 之后返回，不改变 d 的状态（遵循 hash.Hash 契约）。
func (d *digest) Sum(in []byte) []byte {
	// 在副本上做填充与收尾，保证多次调用 Sum 结果一致。
	d0 := *d
	sum := d0.checkSum()
	return append(in, sum[:]...)
}

// checkSum 执行消息填充并输出最终摘要（GB/T 32905-2016 4.2 填充方式）。
func (d *digest) checkSum() [Size]byte {
	bitLen := d.len << 3

	// 填充 0x80，再补 0x00 至长度模 64 等于 56，最后补 8 字节大端比特长度。
	var pad [BlockSize * 2]byte
	pad[0] = 0x80
	padLen := 56 - int(d.len%BlockSize)
	if padLen <= 0 {
		padLen += BlockSize
	}
	binary.BigEndian.PutUint64(pad[padLen:], bitLen)
	_, _ = d.Write(pad[:padLen+8])

	var out [Size]byte
	for i, v := range d.h {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return out
}

func rotl(x uint32, n uint32) uint32 {
	n &= 31
	return x<<n | x>>(32-n)
}

// 布尔函数 FF、GG（GB/T 32905-2016 4.3）。
func ff0(x, y, z uint32) uint32 { return x ^ y ^ z }
func ff1(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
func gg0(x, y, z uint32) uint32 { return x ^ y ^ z }
func gg1(x, y, z uint32) uint32 { return (x & y) | (^x & z) }

// 置换函数 P0、P1（GB/T 32905-2016 4.4）。
func p0(x uint32) uint32 { return x ^ rotl(x, 9) ^ rotl(x, 17) }
func p1(x uint32) uint32 { return x ^ rotl(x, 15) ^ rotl(x, 23) }

// 常量 Tj（GB/T 32905-2016 4.3）。
const (
	t0 = 0x79cc4519 // 0 <= j <= 15
	t1 = 0x7a879d8a // 16 <= j <= 63
)

// block 对若干完整分组执行消息扩展与迭代压缩（GB/T 32905-2016 5.2、5.3）。
func (d *digest) block(p []byte) {
	var w [68]uint32
	var w1 [64]uint32

	for len(p) >= BlockSize {
		// 消息扩展：由 B 生成 W[0..67] 与 W'[0..63]。
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(p[i*4:])
		}
		for i := 16; i < 68; i++ {
			w[i] = p1(w[i-16]^w[i-9]^rotl(w[i-3], 15)) ^ rotl(w[i-13], 7) ^ w[i-6]
		}
		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}

		a, b, c, dd := d.h[0], d.h[1], d.h[2], d.h[3]
		e, f, g, h := d.h[4], d.h[5], d.h[6], d.h[7]

		for i := 0; i < 16; i++ {
			a12 := rotl(a, 12)
			ss1 := rotl(a12+e+rotl(t0, uint32(i)), 7)
			ss2 := ss1 ^ a12
			tt1 := ff0(a, b, c) + dd + ss2 + w1[i]
			tt2 := gg0(e, f, g) + h + ss1 + w[i]
			dd = c
			c = rotl(b, 9)
			b = a
			a = tt1
			h = g
			g = rotl(f, 19)
			f = e
			e = p0(tt2)
		}
		for i := 16; i < 64; i++ {
			a12 := rotl(a, 12)
			ss1 := rotl(a12+e+rotl(t1, uint32(i)), 7)
			ss2 := ss1 ^ a12
			tt1 := ff1(a, b, c) + dd + ss2 + w1[i]
			tt2 := gg1(e, f, g) + h + ss1 + w[i]
			dd = c
			c = rotl(b, 9)
			b = a
			a = tt1
			h = g
			g = rotl(f, 19)
			f = e
			e = p0(tt2)
		}

		// V(i+1) = ABCDEFGH xor V(i)
		d.h[0] ^= a
		d.h[1] ^= b
		d.h[2] ^= c
		d.h[3] ^= dd
		d.h[4] ^= e
		d.h[5] ^= f
		d.h[6] ^= g
		d.h[7] ^= h

		p = p[BlockSize:]
	}
}
