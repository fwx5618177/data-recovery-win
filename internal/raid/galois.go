package raid

// Galois Field GF(2^8) 运算 — 给 RAID 6 Reed-Solomon 双盘缺失重建用。
//
// 生成多项式 0x11D（标准 RS-255 / RAID 6 用的 primitive polynomial）。
// exp/log 表在 init() 预计算，后续所有乘法都是 O(1) 查表。

var (
	gfExp [512]byte // 循环 2 倍长度，避免 mul 里的 mod 255
	gfLog [256]byte
)

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		// x *= 2 in GF(2^8); 溢出时 XOR 0x1D（0x11D 去掉 bit8 后的 reducer）
		hi := x & 0x80
		x <<= 1
		if hi != 0 {
			x ^= 0x1D
		}
	}
	// 循环延伸让 mul 不用 mod
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfMul GF(2^8) 乘法
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfDiv GF(2^8) 除法；b=0 panic（调用方该保证）
func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+255-int(gfLog[b])]
}

// gfPow α^n
func gfPow(n int) byte {
	n = ((n % 255) + 255) % 255
	return gfExp[n]
}

// RAID6PQ P = XOR 所有数据盘字节；Q = α^i·Di 累加
// 调用方传同一 stripe 内每块数据盘的字节切片，长度必须一致。
// 返回 (P, Q)。
func RAID6PQ(dataStripes [][]byte) (p, q []byte) {
	if len(dataStripes) == 0 {
		return nil, nil
	}
	n := len(dataStripes[0])
	p = make([]byte, n)
	q = make([]byte, n)
	for i, d := range dataStripes {
		factor := gfPow(i)
		for j := 0; j < n; j++ {
			p[j] ^= d[j]
			q[j] ^= gfMul(factor, d[j])
		}
	}
	return p, q
}

// RAID6RecoverTwoDataDisks 给同一 stripe 行内：两个数据盘缺（idx x < y），
// P / Q 都在，其它数据盘都在 → 解方程还原 Dx, Dy。
//
// 方程组（GF(2^8) 上）：
//
//	Dx + Dy = A    // A = P XOR (除 x,y 外的其它数据盘)
//	α^x·Dx + α^y·Dy = B   // B = Q XOR (对应的其它数据盘 α^i 项)
//
// 解：
//
//	D_y = (α^x · A + B) / (α^x + α^y)
//	D_x = A + D_y
//
// dataStripes 是全部 N 个数据盘的字节切片（x, y 位置传 nil；其它位置给真实数据）。
// p / q 是该 stripe 行 P / Q 的字节（必有）。
func RAID6RecoverTwoDataDisks(dataStripes [][]byte, p, q []byte, x, y int) (dx, dy []byte, err error) {
	n := len(p)
	if len(q) != n {
		return nil, nil, ErrSizeMismatch
	}
	if x == y || x < 0 || y < 0 || x >= len(dataStripes) || y >= len(dataStripes) {
		return nil, nil, ErrBadIndex
	}
	if x > y {
		x, y = y, x
	}

	A := make([]byte, n)
	B := make([]byte, n)
	for i, d := range dataStripes {
		if i == x || i == y {
			continue
		}
		if d == nil || len(d) != n {
			return nil, nil, ErrSizeMismatch
		}
		factor := gfPow(i)
		for j := 0; j < n; j++ {
			A[j] ^= d[j]
			B[j] ^= gfMul(factor, d[j])
		}
	}
	// A, B 里都已排除 x,y；现在 + P/Q 得到"仅含 Dx + Dy 的方程"
	for j := 0; j < n; j++ {
		A[j] ^= p[j]
		B[j] ^= q[j]
	}
	// 分母 = α^x + α^y
	denom := gfPow(x) ^ gfPow(y)
	if denom == 0 {
		return nil, nil, ErrSingular
	}
	ax := gfPow(x)
	dy = make([]byte, n)
	dx = make([]byte, n)
	for j := 0; j < n; j++ {
		num := gfMul(ax, A[j]) ^ B[j]
		dy[j] = gfDiv(num, denom)
		dx[j] = A[j] ^ dy[j]
	}
	return dx, dy, nil
}

// errors
var (
	ErrSizeMismatch = raidError("数据盘字节切片长度不一致")
	ErrBadIndex     = raidError("缺失盘索引不合法")
	ErrSingular     = raidError("GF 方程无解（x == y 或布局不合法）")
)

type raidError string

func (e raidError) Error() string { return string(e) }
