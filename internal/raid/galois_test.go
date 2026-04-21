package raid

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGFBasic(t *testing.T) {
	if gfMul(0, 5) != 0 || gfMul(5, 0) != 0 {
		t.Error("× 0 应为 0")
	}
	if gfMul(1, 7) != 7 {
		t.Error("× 1 应恒等")
	}
	// 分配律：a·(b+c) == a·b + a·c
	a, b, c := byte(0x53), byte(0xCA), byte(0xF8)
	if gfMul(a, b^c) != gfMul(a, b)^gfMul(a, c) {
		t.Error("GF 分配律失败")
	}
	// 除法逆运算
	for _, x := range []byte{1, 2, 0x80, 0xFF} {
		for _, y := range []byte{1, 2, 0x80, 0xFF} {
			z := gfMul(x, y)
			if gfDiv(z, y) != x {
				t.Errorf("div/mul 不对称 x=%d y=%d", x, y)
			}
		}
	}
}

func TestRAID6PQ_Roundtrip(t *testing.T) {
	const stripe = 128
	const n = 4 // 4 数据盘
	data := make([][]byte, n)
	for i := range data {
		data[i] = make([]byte, stripe)
		rand.Read(data[i])
	}
	p, q := RAID6PQ(data)

	// 模拟缺 disk 1 + disk 3
	data1 := append([]byte{}, data[1]...)
	data3 := append([]byte{}, data[3]...)
	data[1] = nil
	data[3] = nil

	dx, dy, err := RAID6RecoverTwoDataDisks(data, p, q, 1, 3)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !bytes.Equal(dx, data1) {
		t.Errorf("Dx 重建不匹配:\n  got  %x\n  want %x", dx[:16], data1[:16])
	}
	if !bytes.Equal(dy, data3) {
		t.Errorf("Dy 重建不匹配")
	}
}

func TestRAID6PQ_CrossCombinations(t *testing.T) {
	const stripe = 64
	const n = 6
	data := make([][]byte, n)
	for i := range data {
		data[i] = make([]byte, stripe)
		rand.Read(data[i])
	}
	orig := make([][]byte, n)
	for i, d := range data {
		orig[i] = append([]byte{}, d...)
	}
	p, q := RAID6PQ(data)

	// 尝试各种双盘缺失组合
	for x := 0; x < n; x++ {
		for y := x + 1; y < n; y++ {
			// 重置
			work := make([][]byte, n)
			for i := range orig {
				work[i] = append([]byte{}, orig[i]...)
			}
			work[x] = nil
			work[y] = nil
			dx, dy, err := RAID6RecoverTwoDataDisks(work, p, q, x, y)
			if err != nil {
				t.Fatalf("x=%d y=%d: %v", x, y, err)
			}
			if !bytes.Equal(dx, orig[x]) || !bytes.Equal(dy, orig[y]) {
				t.Errorf("x=%d y=%d: 重建不匹配", x, y)
			}
		}
	}
}
