package raid

import (
	"bytes"
	"testing"

	"data-recovery/internal/disk"
	"data-recovery/internal/testutil"
)

// RAID 0 round-trip：把一段已知字节按条带写到两块盘上，再用 Reader 读回应该一致
func TestRAID0_TwoDisksReadBack(t *testing.T) {
	const stripe = int64(64) // 小条带便于验证
	// "原始数据" 256 字节 = 4 条带（disk0/disk1 各 2 条带）
	original := make([]byte, 256)
	for i := range original {
		original[i] = byte(i)
	}
	// 手工拆分
	disk0 := make([]byte, 128)
	disk1 := make([]byte, 128)
	// stripe 0 → disk0[0:64]
	copy(disk0[0:64], original[0:64])
	// stripe 1 → disk1[0:64]
	copy(disk1[0:64], original[64:128])
	// stripe 2 → disk0[64:128]
	copy(disk0[64:128], original[128:192])
	// stripe 3 → disk1[64:128]
	copy(disk1[64:128], original[192:256])

	r, err := NewReader(Config{
		Level:       Level0,
		Disks:       []disk.DiskReader{testutil.NewMemReader(disk0), testutil.NewMemReader(disk1)},
		StripeBytes: stripe,
	})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	for _, c := range []struct {
		off int64
		ln  int
	}{
		{0, 256},
		{0, 64},     // 单 stripe 内
		{32, 64},    // 跨 stripe（disk0 → disk1）
		{100, 80},   // 跨 stripe 中间
		{200, 56},
	} {
		got := make([]byte, c.ln)
		n, _ := r.ReadAt(got, c.off)
		if n != c.ln {
			t.Errorf("off=%d len=%d: 读字节数 %d", c.off, c.ln, n)
		}
		if !bytes.Equal(got, original[c.off:c.off+int64(c.ln)]) {
			t.Errorf("off=%d len=%d: 数据不一致\n  got  %x\n  want %x",
				c.off, c.ln, got, original[c.off:c.off+int64(c.ln)])
		}
	}
}

// RAID 1：从可用镜像读回原始数据
func TestRAID1_ReadFromMirror(t *testing.T) {
	original := make([]byte, 1024)
	for i := range original {
		original[i] = byte(i ^ 0x5A)
	}
	r, err := NewReader(Config{
		Level: Level1,
		Disks: []disk.DiskReader{testutil.NewMemReader(original), nil}, // 第二盘缺失
	})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got := make([]byte, 1024)
	n, _ := r.ReadAt(got, 0)
	if n != 1024 || !bytes.Equal(got, original) {
		t.Errorf("RAID 1 镜像读不一致")
	}
}

// RAID 5 三盘 left-symmetric round-trip：合成 + 全盘读 + 缺一盘重建
func TestRAID5_ThreeDisksLeftSymmetric_RebuildMissing(t *testing.T) {
	const stripe = int64(64)
	const rows = int64(4)
	const dataPerRow = int64(2)            // 3 盘 - 1 校验
	logicalSize := stripe * rows * dataPerRow // 64 * 4 * 2 = 512

	// 准备原始 logical 数据
	original := make([]byte, logicalSize)
	for i := range original {
		original[i] = byte(i)
	}

	// 手工把数据放到 3 盘 + 计算 parity
	disk0 := make([]byte, rows*stripe)
	disk1 := make([]byte, rows*stripe)
	disk2 := make([]byte, rows*stripe)
	disks := [3][]byte{disk0, disk1, disk2}

	for row := int64(0); row < rows; row++ {
		// left-symmetric：parity 列 = (n - 1 - row%n) % n
		parityCol := (3 - 1 - row%3 + 3) % 3
		// 行内 col 0/1 → 实际 disk = (parityCol+1+col) % 3
		var dataCols [2]int64
		dataCols[0] = (parityCol + 1) % 3
		dataCols[1] = (parityCol + 2) % 3

		// 把 logical 数据写入数据盘
		for c := int64(0); c < dataPerRow; c++ {
			logStripeIdx := row*dataPerRow + c
			src := original[logStripeIdx*stripe : (logStripeIdx+1)*stripe]
			copy(disks[dataCols[c]][row*stripe:(row+1)*stripe], src)
		}
		// 计算 parity 写入校验盘
		par := make([]byte, stripe)
		for c := int64(0); c < dataPerRow; c++ {
			d := disks[dataCols[c]][row*stripe : (row+1)*stripe]
			for i := range par {
				par[i] ^= d[i]
			}
		}
		copy(disks[parityCol][row*stripe:(row+1)*stripe], par)
	}

	// 全盘可用：直接读
	r, err := NewReader(Config{
		Level:       Level5,
		StripeBytes: stripe,
		Disks: []disk.DiskReader{
			testutil.NewMemReader(disk0),
			testutil.NewMemReader(disk1),
			testutil.NewMemReader(disk2),
		},
	})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got := make([]byte, logicalSize)
	n, _ := r.ReadAt(got, 0)
	if n != int(logicalSize) {
		t.Fatalf("全盘读字节数 %d", n)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("RAID 5 全盘读不一致")
	}

	// 缺 disk1：重建后应等于原始数据
	r2, err := NewReader(Config{
		Level:       Level5,
		StripeBytes: stripe,
		Disks: []disk.DiskReader{
			testutil.NewMemReader(disk0),
			nil,
			testutil.NewMemReader(disk2),
		},
	})
	if err != nil {
		t.Fatalf("NewReader missing: %v", err)
	}
	got2 := make([]byte, logicalSize)
	n, _ = r2.ReadAt(got2, 0)
	if n != int(logicalSize) {
		t.Fatalf("重建读字节数 %d", n)
	}
	if !bytes.Equal(got2, original) {
		t.Errorf("RAID 5 缺 disk1 重建结果不一致\n  got  %x\n  want %x",
			got2[:32], original[:32])
	}
}

func TestRAID0_RejectsNilDisk(t *testing.T) {
	_, err := NewReader(Config{
		Level:       Level0,
		StripeBytes: 64,
		Disks:       []disk.DiskReader{testutil.NewMemReader(nil), nil},
	})
	if err == nil {
		t.Error("RAID 0 应拒绝缺盘")
	}
}

// RAID 6 双数据盘缺失：合成 P+Q，故意缺 2 个数据盘，读整个阵列应得原始字节
func TestRAID6_TwoDataDisksMissingRebuild(t *testing.T) {
	const stripe = int64(64)
	const n = int64(5) // 5 盘 = 3 数据 + P + Q
	const rows = int64(2)
	const dataPerRow = int64(3)
	logicalSize := stripe * rows * dataPerRow

	original := make([]byte, logicalSize)
	for i := range original {
		original[i] = byte(i*13 + 7)
	}

	// 手工布置 N 个盘 的字节（模拟 left-symmetric RAID 6）
	disks := make([][]byte, n)
	for i := range disks {
		disks[i] = make([]byte, rows*stripe)
	}

	for row := int64(0); row < rows; row++ {
		pCol := (n - 1 - row%n + n) % n
		qCol := (n - 2 - row%n + n) % n
		dataCols := raid6DataCols(n, pCol, qCol)
		_ = dataCols // 保持与 Reader 同算法
		// 写入数据 + 算 P/Q
		dataStripes := make([][]byte, dataPerRow)
		for k := int64(0); k < dataPerRow; k++ {
			logStripe := row*dataPerRow + k
			src := original[logStripe*stripe : (logStripe+1)*stripe]
			copy(disks[dataCols[k]][row*stripe:(row+1)*stripe], src)
			dataStripes[k] = src
		}
		p, q := RAID6PQ(dataStripes)
		copy(disks[pCol][row*stripe:(row+1)*stripe], p)
		copy(disks[qCol][row*stripe:(row+1)*stripe], q)
	}

	// 缺 2 个数据盘：0 和 2（取决于 row 0 的 dataCols，这里保证它们在数据列中）
	readers := make([]disk.DiskReader, n)
	for i := int64(0); i < n; i++ {
		readers[i] = testutil.NewMemReader(disks[i])
	}
	// 简化：让 row 0 的 qCol=3, pCol=4，dataCols=[0,1,2]；缺 0 + 2
	readers[0] = nil
	readers[2] = nil

	r, err := NewReader(Config{
		Level:       Level6,
		StripeBytes: stripe,
		Disks:       readers,
	})
	if err != nil {
		t.Fatalf("NewReader RAID6: %v", err)
	}
	got := make([]byte, logicalSize)
	nRead, _ := r.ReadAt(got, 0)
	if nRead != int(logicalSize) {
		t.Fatalf("读字节数 %d want %d", nRead, logicalSize)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("RAID 6 双缺重建不匹配\n  got  %x\n  want %x", got[:32], original[:32])
	}
}

func TestRAID5_RejectsTwoMissing(t *testing.T) {
	_, err := NewReader(Config{
		Level:       Level5,
		StripeBytes: 64,
		Disks:       []disk.DiskReader{nil, nil, testutil.NewMemReader(make([]byte, 256))},
	})
	if err == nil {
		t.Error("RAID 5 应拒绝缺 2 盘")
	}
}
