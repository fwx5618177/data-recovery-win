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
