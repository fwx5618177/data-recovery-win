package zfs

import (
	"bytes"
	"testing"
)

// RAIDZ1 round-trip: 构造 P = XOR(data)；任意缺一盘都能还原
func TestRAIDZ1_ReconstructAnyOne(t *testing.T) {
	d1 := []byte{0x01, 0x02, 0x03, 0x04, 0xFF}
	d2 := []byte{0x10, 0x20, 0x30, 0x40, 0xAA}
	d3 := []byte{0xAB, 0xCD, 0xEF, 0x12, 0x55}
	// P = XOR(d1,d2,d3)
	p := make([]byte, len(d1))
	for i := range p {
		p[i] = d1[i] ^ d2[i] ^ d3[i]
	}
	cases := []struct {
		name    string
		missing int
	}{
		{"miss P", 0}, {"miss d1", 1}, {"miss d2", 2}, {"miss d3", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cols := [][]byte{p, d1, d2, d3}
			cols[c.missing] = nil
			got, err := ReconstructRAIDZ1(cols, c.missing)
			if err != nil {
				t.Fatalf("%v", err)
			}
			want := [][]byte{p, d1, d2, d3}[c.missing]
			if !bytes.Equal(got, want) {
				t.Errorf("missing=%d\n got %x\nwant %x", c.missing, got, want)
			}
		})
	}
}

// RAIDZ2 单缺：P 缺 / Q 缺 / data 缺
func TestRAIDZ2_SingleMissing(t *testing.T) {
	// 3 data disks
	d0 := []byte{0x11, 0x22, 0x33, 0x44}
	d1 := []byte{0x55, 0x66, 0x77, 0x88}
	d2 := []byte{0x99, 0xAA, 0xBB, 0xCC}
	// 计算 P, Q
	p := make([]byte, len(d0))
	q := make([]byte, len(d0))
	for i := range p {
		p[i] = d0[i] ^ d1[i] ^ d2[i]
		q[i] = gfMul(zfsGFExp[0], d0[i]) ^ gfMul(zfsGFExp[1], d1[i]) ^ gfMul(zfsGFExp[2], d2[i])
	}

	tests := []struct {
		name    string
		missing int
	}{
		{"miss P", 0}, {"miss Q", 1}, {"miss d0", 2}, {"miss d1", 3}, {"miss d2", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cols := [][]byte{p, q, d0, d1, d2}
			saved := make([]byte, len(cols[tt.missing]))
			copy(saved, cols[tt.missing])
			cols[tt.missing] = nil
			if err := ReconstructRAIDZ2(cols, []int{tt.missing}); err != nil {
				t.Fatalf("%v", err)
			}
			if !bytes.Equal(cols[tt.missing], saved) {
				t.Errorf("%s: got %x want %x", tt.name, cols[tt.missing], saved)
			}
		})
	}
}

// RAIDZ2 双 data 缺
func TestRAIDZ2_TwoDataMissing(t *testing.T) {
	d0 := []byte{0x11, 0x22, 0x33, 0x44}
	d1 := []byte{0x55, 0x66, 0x77, 0x88}
	d2 := []byte{0x99, 0xAA, 0xBB, 0xCC}
	d3 := []byte{0xDD, 0xEE, 0xFF, 0x00}

	p := make([]byte, len(d0))
	q := make([]byte, len(d0))
	for i := range p {
		p[i] = d0[i] ^ d1[i] ^ d2[i] ^ d3[i]
		q[i] = gfMul(zfsGFExp[0], d0[i]) ^ gfMul(zfsGFExp[1], d1[i]) ^
			gfMul(zfsGFExp[2], d2[i]) ^ gfMul(zfsGFExp[3], d3[i])
	}

	// 缺 d1 + d3（index 3, 5）
	cols := [][]byte{p, q, d0, d1, d2, d3}
	d1Saved := make([]byte, len(d1))
	d3Saved := make([]byte, len(d3))
	copy(d1Saved, d1)
	copy(d3Saved, d3)

	cols[3] = nil
	cols[5] = nil
	if err := ReconstructRAIDZ2(cols, []int{3, 5}); err != nil {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(cols[3], d1Saved) {
		t.Errorf("d1:\n got %x\nwant %x", cols[3], d1Saved)
	}
	if !bytes.Equal(cols[5], d3Saved) {
		t.Errorf("d3:\n got %x\nwant %x", cols[5], d3Saved)
	}
}

// RAIDZ3 三 data 同时缺失：core test case（3×3 Vandermonde 求逆）
func TestRAIDZ3_ThreeDataMissing(t *testing.T) {
	d0 := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	d1 := []byte{0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}
	d2 := []byte{0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22}
	d3 := []byte{0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	d4 := []byte{0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	dataLen := len(d0)

	// 计算 P, Q, R
	p := make([]byte, dataLen)
	q := make([]byte, dataLen)
	r := make([]byte, dataLen)
	datas := [][]byte{d0, d1, d2, d3, d4}
	for k, d := range datas {
		aK := zfsGFExp[k%255]
		bK := gfMul(aK, aK)
		for j := 0; j < dataLen; j++ {
			p[j] ^= d[j]
			q[j] ^= gfMul(aK, d[j])
			r[j] ^= gfMul(bK, d[j])
		}
	}

	// 缺 d0(col=3), d2(col=5), d4(col=7)
	cols := [][]byte{p, q, r, d0, d1, d2, d3, d4}
	saved0 := make([]byte, dataLen)
	saved2 := make([]byte, dataLen)
	saved4 := make([]byte, dataLen)
	copy(saved0, d0)
	copy(saved2, d2)
	copy(saved4, d4)

	cols[3] = nil
	cols[5] = nil
	cols[7] = nil
	if err := ReconstructRAIDZ3(cols, []int{3, 5, 7}); err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if !bytes.Equal(cols[3], saved0) {
		t.Errorf("d0:\n got %x\nwant %x", cols[3], saved0)
	}
	if !bytes.Equal(cols[5], saved2) {
		t.Errorf("d2:\n got %x\nwant %x", cols[5], saved2)
	}
	if !bytes.Equal(cols[7], saved4) {
		t.Errorf("d4:\n got %x\nwant %x", cols[7], saved4)
	}
}

// RAIDZ3 case B: 2 parity + 1 data 缺
func TestRAIDZ3_TwoParityOneData(t *testing.T) {
	d0 := []byte{0x11, 0x22, 0x33, 0x44}
	d1 := []byte{0x55, 0x66, 0x77, 0x88}
	d2 := []byte{0x99, 0xAA, 0xBB, 0xCC}

	p := make([]byte, len(d0))
	q := make([]byte, len(d0))
	r := make([]byte, len(d0))
	datas := [][]byte{d0, d1, d2}
	for k, d := range datas {
		aK := zfsGFExp[k%255]
		bK := gfMul(aK, aK)
		for j := 0; j < len(d0); j++ {
			p[j] ^= d[j]
			q[j] ^= gfMul(aK, d[j])
			r[j] ^= gfMul(bK, d[j])
		}
	}

	// 缺 P(0), Q(1), d1(4) —— 剩 R 解 d1
	cols := [][]byte{p, q, r, d0, d1, d2}
	pSaved, qSaved, d1Saved := make([]byte, 4), make([]byte, 4), make([]byte, 4)
	copy(pSaved, p)
	copy(qSaved, q)
	copy(d1Saved, d1)

	cols[0] = nil
	cols[1] = nil
	cols[4] = nil
	if err := ReconstructRAIDZ3(cols, []int{0, 1, 4}); err != nil {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(cols[0], pSaved) || !bytes.Equal(cols[1], qSaved) || !bytes.Equal(cols[4], d1Saved) {
		t.Errorf("case B 未正确重建")
	}
}

// RAIDZ3 case C: 1 parity + 2 data 缺
func TestRAIDZ3_OneParityTwoData(t *testing.T) {
	d0 := []byte{0x11, 0x22, 0x33, 0x44}
	d1 := []byte{0x55, 0x66, 0x77, 0x88}
	d2 := []byte{0x99, 0xAA, 0xBB, 0xCC}
	d3 := []byte{0xDD, 0xEE, 0xFF, 0x00}

	p := make([]byte, len(d0))
	q := make([]byte, len(d0))
	r := make([]byte, len(d0))
	datas := [][]byte{d0, d1, d2, d3}
	for k, d := range datas {
		aK := zfsGFExp[k%255]
		bK := gfMul(aK, aK)
		for j := 0; j < len(d0); j++ {
			p[j] ^= d[j]
			q[j] ^= gfMul(aK, d[j])
			r[j] ^= gfMul(bK, d[j])
		}
	}

	// 缺 R(2), d0(3), d2(5) —— 剩 P+Q 解 d0+d2
	cols := [][]byte{p, q, r, d0, d1, d2, d3}
	rSaved, d0Saved, d2Saved := make([]byte, 4), make([]byte, 4), make([]byte, 4)
	copy(rSaved, r)
	copy(d0Saved, d0)
	copy(d2Saved, d2)

	cols[2] = nil
	cols[3] = nil
	cols[5] = nil
	if err := ReconstructRAIDZ3(cols, []int{2, 3, 5}); err != nil {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(cols[2], rSaved) || !bytes.Equal(cols[3], d0Saved) || !bytes.Equal(cols[5], d2Saved) {
		t.Errorf("case C 未正确重建")
	}
}

// GF(2^8) 3×3 矩阵求逆单测
func TestGF256Invert3x3(t *testing.T) {
	// Vandermonde matrix: row1 = [1,1,1], row2 = [2,3,4], row3 = [4,9,16 in GF]
	// 在 GF(2^8) 里 2²=4, 3²=5 (因为 GF 里 3²=9 → mod 约 0x1D 后 = 5), 4²=16
	a, b, c := byte(2), byte(3), byte(4)
	v := [3][3]byte{
		{1, 1, 1},
		{a, b, c},
		{gfMul(a, a), gfMul(b, b), gfMul(c, c)},
	}
	inv, err := gf256Invert3x3(v)
	if err != nil {
		t.Fatalf("invert: %v", err)
	}
	// V · inv 应等 I
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			sum := byte(0)
			for k := 0; k < 3; k++ {
				sum ^= gfMul(v[i][k], inv[k][j])
			}
			expected := byte(0)
			if i == j {
				expected = 1
			}
			if sum != expected {
				t.Errorf("V·inv[%d][%d] = %d want %d", i, j, sum, expected)
			}
		}
	}
}

// RAIDZ2 P+data 缺
func TestRAIDZ2_PAndDataMissing(t *testing.T) {
	d0 := []byte{0x11, 0x22, 0x33, 0x44}
	d1 := []byte{0x55, 0x66, 0x77, 0x88}
	d2 := []byte{0x99, 0xAA, 0xBB, 0xCC}

	p := make([]byte, len(d0))
	q := make([]byte, len(d0))
	for i := range p {
		p[i] = d0[i] ^ d1[i] ^ d2[i]
		q[i] = gfMul(zfsGFExp[0], d0[i]) ^ gfMul(zfsGFExp[1], d1[i]) ^ gfMul(zfsGFExp[2], d2[i])
	}

	// 缺 P（0）+ d1（3）
	cols := [][]byte{p, q, d0, d1, d2}
	pSaved := make([]byte, len(p))
	d1Saved := make([]byte, len(d1))
	copy(pSaved, p)
	copy(d1Saved, d1)

	cols[0] = nil
	cols[3] = nil
	if err := ReconstructRAIDZ2(cols, []int{0, 3}); err != nil {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(cols[0], pSaved) {
		t.Errorf("P:\n got %x\nwant %x", cols[0], pSaved)
	}
	if !bytes.Equal(cols[3], d1Saved) {
		t.Errorf("d1:\n got %x\nwant %x", cols[3], d1Saved)
	}
}
