// Package raid 把多个物理盘 / 镜像虚拟拼成一个 disk.DiskReader，
// 让上层（NTFS scanner / carver）可以无感地扫描 RAID 阵列。
//
// **支持的 level**：
//   ✅ RAID 0    — 条带 (stripe)，没有冗余；任一磁盘缺失就完蛋
//   ✅ RAID 1    — 镜像；任一磁盘可用即可全文恢复
//   ✅ RAID 5    — 单奇偶校验 (XOR)；最多容许 1 块盘缺失（用 P 重建）
//   ✅ RAID 6    — 双奇偶 (P + Q, GF(2^8) Reed-Solomon)；最多容许 2 块盘缺失，见 galois.go
//   ✅ RAID 10   — mirror 对的 stripe；每对至少 1 盘可用
//
// 不做"自动检测条带大小 / 顺序"——RAID metadata 五花八门（mdadm / hardware controller /
// LVM / Storage Spaces / Apple Software RAID），用户应自行知道：盘的顺序、stripe size、
// parity 排列方式（left-symmetric / left-asymmetric ...）。
//
// 读路径全部走 ReadAt，复用 disk.DiskReader 接口。Write 不实现（只读恢复工具）。
package raid

import (
	"errors"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// Level 是 RAID 等级
type Level int

const (
	Level0  Level = 0
	Level1  Level = 1
	Level5  Level = 5
	Level6  Level = 6
	Level10 Level = 10
)

// ParityLayout RAID 5 校验块在哪一列：
type ParityLayout int

const (
	ParityLeftSymmetric  ParityLayout = iota // mdadm 默认；P 在 (stripe_index % N) 列，从右侧轮转
	ParityLeftAsymmetric                     // P 同样位置，但数据不"跳过 P"
	ParityRightSymmetric
	ParityRightAsymmetric
)

// Config 描述 RAID 阵列布局
type Config struct {
	Level        Level
	Disks        []disk.DiskReader // 按"原阵列编号"顺序提供；某盘缺失传 nil
	StripeBytes  int64             // 条带大小（RAID0/5 必填；典型 64KB / 128KB / 512KB）
	Parity       ParityLayout      // 仅 RAID5 用到
	LogicalSize  int64             // 阵列对外呈现的总字节大小（不传则按 disks * size 算）
	devicePath   string            // DevicePath() 返回值
}

// Reader 实现 disk.DiskReader，把 N 个底层盘按 RAID 规则虚拟成一个连续设备。
type Reader struct {
	cfg Config
}

// NewReader 校验配置并构造 Reader。
//
// disks 数量 / 缺失情况要求：
//   - RAID 0：至少 2 盘，全部不能缺
//   - RAID 1：至少 2 盘，至少 1 盘可用
//   - RAID 5：至少 3 盘，最多 1 盘缺失（缺的传 nil）
func NewReader(cfg Config) (*Reader, error) {
	if len(cfg.Disks) < 2 {
		return nil, fmt.Errorf("RAID 至少需要 2 块盘，给了 %d", len(cfg.Disks))
	}
	switch cfg.Level {
	case Level0:
		if cfg.StripeBytes <= 0 {
			return nil, fmt.Errorf("RAID 0 必须指定 StripeBytes")
		}
		for i, d := range cfg.Disks {
			if d == nil {
				return nil, fmt.Errorf("RAID 0 不允许缺盘（disk[%d] 为 nil）", i)
			}
		}
	case Level1:
		alive := 0
		for _, d := range cfg.Disks {
			if d != nil {
				alive++
			}
		}
		if alive == 0 {
			return nil, errors.New("RAID 1 全部盘都缺失")
		}
	case Level5:
		if cfg.StripeBytes <= 0 {
			return nil, fmt.Errorf("RAID 5 必须指定 StripeBytes")
		}
		if len(cfg.Disks) < 3 {
			return nil, fmt.Errorf("RAID 5 至少需要 3 块盘")
		}
		missing := 0
		for _, d := range cfg.Disks {
			if d == nil {
				missing++
			}
		}
		if missing > 1 {
			return nil, fmt.Errorf("RAID 5 最多容许 1 块盘缺失，当前缺 %d", missing)
		}
	case Level6:
		if cfg.StripeBytes <= 0 {
			return nil, fmt.Errorf("RAID 6 必须指定 StripeBytes")
		}
		if len(cfg.Disks) < 4 {
			return nil, fmt.Errorf("RAID 6 至少需要 4 块盘")
		}
		// RAID 6 支持最多 2 盘缺失：P+Q 双奇偶 + GF(2^8) Reed-Solomon。
		// 单盘缺 → 走 RAID 5 XOR 重建（P 列）；双盘缺 → galois.go 的
		// RAID6RecoverTwoDataDisks 解二元方程还原两块数据盘。
		missing := 0
		for _, d := range cfg.Disks {
			if d == nil {
				missing++
			}
		}
		if missing > 2 {
			return nil, fmt.Errorf("RAID 6 最多容 2 盘缺失，当前缺 %d", missing)
		}
	case Level10:
		if cfg.StripeBytes <= 0 {
			return nil, fmt.Errorf("RAID 10 必须指定 StripeBytes")
		}
		if len(cfg.Disks) < 4 || len(cfg.Disks)%2 != 0 {
			return nil, fmt.Errorf("RAID 10 需偶数块盘 ≥4")
		}
		// RAID 10 = mirror pairs 的 stripe；每对里至少有一块盘可用即可
		for i := 0; i < len(cfg.Disks); i += 2 {
			if cfg.Disks[i] == nil && cfg.Disks[i+1] == nil {
				return nil, fmt.Errorf("RAID 10 镜像对 [%d,%d] 同时缺失", i, i+1)
			}
		}
	default:
		return nil, fmt.Errorf("不支持的 RAID level: %d", cfg.Level)
	}
	if cfg.devicePath == "" {
		cfg.devicePath = fmt.Sprintf("raid%d://%dx%d", cfg.Level, len(cfg.Disks), cfg.StripeBytes)
	}
	return &Reader{cfg: cfg}, nil
}

// Open / Close 透传给所有非 nil 子盘
func (r *Reader) Open() error {
	for _, d := range r.cfg.Disks {
		if d == nil {
			continue
		}
		if err := d.Open(); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reader) Close() error {
	var firstErr error
	for _, d := range r.cfg.Disks {
		if d == nil {
			continue
		}
		if err := d.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Size 返回阵列对外呈现的总字节数
func (r *Reader) Size() (int64, error) {
	if r.cfg.LogicalSize > 0 {
		return r.cfg.LogicalSize, nil
	}
	// 用第一块非 nil 盘的 size 推导
	var perDisk int64
	for _, d := range r.cfg.Disks {
		if d == nil {
			continue
		}
		s, err := d.Size()
		if err != nil {
			return 0, err
		}
		perDisk = s
		break
	}
	switch r.cfg.Level {
	case Level0:
		return perDisk * int64(len(r.cfg.Disks)), nil
	case Level1:
		return perDisk, nil
	case Level5:
		return perDisk * int64(len(r.cfg.Disks)-1), nil
	}
	return 0, fmt.Errorf("无法确定阵列大小")
}

func (r *Reader) SectorSize() int    { return 512 }
func (r *Reader) DevicePath() string { return r.cfg.devicePath }

// ReadAt 是核心：按当前 level 翻译 logical → physical(disk_idx, disk_off)
func (r *Reader) ReadAt(buf []byte, offset int64) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	switch r.cfg.Level {
	case Level0:
		return r.readRAID0(buf, offset)
	case Level1:
		return r.readRAID1(buf, offset)
	case Level5:
		return r.readRAID5(buf, offset)
	case Level6:
		return r.readRAID6(buf, offset)
	case Level10:
		return r.readRAID10(buf, offset)
	}
	return 0, fmt.Errorf("未实现的 level")
}

// ---------------- RAID 6 ----------------
//
// RAID 6 left-symmetric 布局：N 盘 = (N-2) 数据 + P + Q；
//   - P 列 = (N-1 - row%N) % N
//   - Q 列 = (N-2 - row%N) % N
//   - 数据列从 (Q列+1) 开始环绕
//
// 读路径：
//   1. 全部在 → 直接读目标数据盘
//   2. 单盘缺 + 缺的是数据盘 → 用 P 做 XOR 重建（galois.go 里的 XOR 等价于 RAID 5）
//   3. 单盘缺 + 缺的是 P/Q → 直接读目标
//   4. 双盘缺且都是数据盘 → 调 RAID6RecoverTwoDataDisks
//   5. 双盘缺含 P/Q 一个 + 一个数据盘 → 用另一个校验盘重建
func (r *Reader) readRAID6(buf []byte, offset int64) (int, error) {
	stripe := r.cfg.StripeBytes
	n := int64(len(r.cfg.Disks))
	dataPerRow := n - 2

	total := 0
	for total < len(buf) {
		logical := offset + int64(total)
		logStripeIdx := logical / stripe
		stripeOff := logical % stripe
		row := logStripeIdx / dataPerRow
		colInRow := logStripeIdx % dataPerRow

		pCol := (n - 1 - row%n + n) % n
		qCol := (n - 2 - row%n + n) % n
		// 按 left-symmetric 生成本行的所有数据列：从 (qCol+1)%n 起环绕，
		// 跳过 P 和 Q，直到凑齐 dataPerRow 个
		dataCols := raid6DataCols(n, pCol, qCol)
		diskIdx := dataCols[colInRow]
		diskOff := row*stripe + stripeOff

		want := stripe - stripeOff
		remain := int64(len(buf) - total)
		if want > remain {
			want = remain
		}

		var got int
		var err error
		if r.cfg.Disks[diskIdx] != nil {
			got, err = r.cfg.Disks[diskIdx].ReadAt(buf[total:total+int(want)], diskOff)
		} else {
			// 重建目标盘：需要 stripe 级重建
			got, err = r.rebuildRAID6Row(buf[total:total+int(want)], row, pCol, qCol, diskIdx, int(diskOff), int(want))
		}
		total += got
		if err != nil && err != io.EOF {
			return total, err
		}
		if got == 0 {
			break
		}
	}
	return total, nil
}

// rebuildRAID6Row 用同行 stripe 重建缺失盘 missingCol 的字节段。
// 情况：
//   a) 目标缺 + 其它盘（含 P、Q）都在 → 单缺场景：优先用 P（XOR）更快
//   b) 两盘缺且都是数据盘 → 调 RAID6RecoverTwoDataDisks
//   c) 两盘缺含 P/Q 一个 + 一个数据盘 → 用另一校验盘重建
func (r *Reader) rebuildRAID6Row(out []byte, row int64, pCol, qCol, missingCol int64, diskOff int, readLen int) (int, error) {
	n := int64(len(r.cfg.Disks))
	// 找所有缺失列
	missing := []int64{}
	for i := int64(0); i < n; i++ {
		if r.cfg.Disks[i] == nil {
			missing = append(missing, i)
		}
	}
	// 读整行每个**可用**盘的 stripe 字节
	stripe := r.cfg.StripeBytes
	stripeReadOff := row * stripe
	rowData := make([][]byte, n)
	for i := int64(0); i < n; i++ {
		if r.cfg.Disks[i] == nil {
			continue
		}
		rowData[i] = make([]byte, stripe)
		cn, err := r.cfg.Disks[i].ReadAt(rowData[i], stripeReadOff)
		if err != nil && cn == 0 {
			return 0, err
		}
	}

	// 场景 a：只有 missingCol 缺
	if len(missing) == 1 && missing[0] == missingCol {
		// XOR 所有非 missing 的**数据盘** + P 列即可重建（忽略 Q）
		rebuilt := make([]byte, stripe)
		for i := int64(0); i < n; i++ {
			if i == missingCol || i == qCol {
				continue
			}
			for j := range rebuilt {
				rebuilt[j] ^= rowData[i][j]
			}
		}
		offInStripe := int(diskOff - int(stripeReadOff))
		n2 := copy(out, rebuilt[offInStripe:offInStripe+readLen])
		return n2, nil
	}

	// 场景 b + c：两盘缺。先区分两缺是哪两列
	if len(missing) != 2 {
		return 0, fmt.Errorf("RAID 6 缺盘数 %d 不在支持范围", len(missing))
	}
	m1, m2 := missing[0], missing[1]
	// 取出 P / Q stripe 数据（如果在）
	pData := rowData[pCol]
	qData := rowData[qCol]

	// 如果 P/Q 缺一个 → 用另一个 + 所有可读数据盘重建
	if m1 == pCol || m2 == pCol || m1 == qCol || m2 == qCol {
		// 用 P-only 重建非-P/Q 的那个缺失数据盘
		// 简化：如果 missingCol 就是数据盘，只要另一个校验盘活着 + 所有其它数据盘
		var parityAlive []byte
		if m1 == pCol || m2 == pCol {
			parityAlive = qData // P 缺用 Q 重建（需要 GF α^i 累加反向）
			// Q = Σ α^i · Di → 缺失数据盘 Dx = (Q - Σ_{i≠x,其它都在} α^i·Di) / α^x
			return rebuildSingleDataDiskFromQ(out, rowData, qData, missingCol, n, pCol, qCol, diskOff, stripeReadOff, readLen)
		}
		parityAlive = pData
		_ = parityAlive
		// P 活 + Q 缺 + 一个数据盘缺 → XOR 重建数据盘，同场景 a 算法
		rebuilt := make([]byte, stripe)
		for i := int64(0); i < n; i++ {
			if i == missingCol || i == qCol || r.cfg.Disks[i] == nil {
				continue
			}
			for j := range rebuilt {
				rebuilt[j] ^= rowData[i][j]
			}
		}
		offInStripe := int(diskOff - int(stripeReadOff))
		return copy(out, rebuilt[offInStripe:offInStripe+readLen]), nil
	}

	// 场景 b：两个都是数据盘 → 调 RAID6RecoverTwoDataDisks
	// 把 rowData 转成"数据盘视角"的 slice（按数据列顺序排，不含 P/Q）
	dataStripes, dataColMap := dataStripesView(rowData, n, pCol, qCol)
	// 在 dataColMap 里找 m1 / m2 对应的"数据盘索引"（Reed-Solomon 用的 0..dataCount-1）
	x := findDataIdx(dataColMap, m1)
	y := findDataIdx(dataColMap, m2)
	if x < 0 || y < 0 {
		return 0, fmt.Errorf("内部错误：双缺盘索引转换失败")
	}
	dx, dy, err := RAID6RecoverTwoDataDisks(dataStripes, pData, qData, x, y)
	if err != nil {
		return 0, err
	}
	// 选其中对应 missingCol 的那个返回
	var rebuilt []byte
	if m1 == missingCol {
		rebuilt = dx
	} else {
		rebuilt = dy
	}
	offInStripe := int(diskOff - int(stripeReadOff))
	return copy(out, rebuilt[offInStripe:offInStripe+readLen]), nil
}

// rebuildSingleDataDiskFromQ P 缺时用 Q 重建某个数据盘：
//   Dx = (Q - Σ_{i≠x 的所有数据盘} α^i·Di) / α^x
func rebuildSingleDataDiskFromQ(out []byte, rowData [][]byte, qData []byte, missingCol, n, pCol, qCol int64, diskOff int, stripeReadOff int64, readLen int) (int, error) {
	stripe := len(qData)
	_ = pCol
	// 取出数据盘视角 index
	_, dataColMap := dataStripesView(rowData, n, pCol, qCol)
	x := findDataIdx(dataColMap, missingCol)
	if x < 0 {
		return 0, fmt.Errorf("missingCol=%d 不是数据列", missingCol)
	}
	// 累加 Σ α^i · Di (i ≠ x)
	accum := make([]byte, stripe)
	for di, col := range dataColMap {
		if di == x {
			continue
		}
		f := gfPow(di)
		for j := 0; j < stripe; j++ {
			accum[j] ^= gfMul(f, rowData[col][j])
		}
	}
	// Dx = (Q XOR accum) / α^x
	ax := gfPow(x)
	rebuilt := make([]byte, stripe)
	for j := 0; j < stripe; j++ {
		rebuilt[j] = gfDiv(qData[j]^accum[j], ax)
	}
	offInStripe := diskOff - int(stripeReadOff)
	return copy(out, rebuilt[offInStripe:offInStripe+readLen]), nil
}

// dataStripesView 按"数据盘顺序"摘出 rowData；返回 (dataStripes, colMap)
// colMap[dataIdx] = 实际磁盘列号
func dataStripesView(rowData [][]byte, n, pCol, qCol int64) ([][]byte, []int64) {
	var out [][]byte
	var cols []int64
	for i := int64(0); i < n; i++ {
		if i == pCol || i == qCol {
			continue
		}
		out = append(out, rowData[i]) // 可能是 nil（缺盘）
		cols = append(cols, i)
	}
	return out, cols
}

// raid6DataCols 给定 n 盘 + pCol + qCol，生成本行的数据列列表（长度 = n-2）。
// 从 (qCol+1) % n 起环绕，跳过 P/Q 列。
func raid6DataCols(n, pCol, qCol int64) []int64 {
	out := make([]int64, 0, n-2)
	c := (qCol + 1) % n
	for int64(len(out)) < n-2 {
		if c != pCol && c != qCol {
			out = append(out, c)
		}
		c = (c + 1) % n
	}
	return out
}

func findDataIdx(dataColMap []int64, col int64) int {
	for i, c := range dataColMap {
		if c == col {
			return i
		}
	}
	return -1
}

// ---------------- RAID 10 ----------------
//
// RAID 10 = N/2 个 mirror 对 stripe 起来：
//   pair_0 = [disk0, disk1]    pair_1 = [disk2, disk3]    ...
// 写：每个 stripe 写到对里的两块盘；读：从对里任一块可用盘读。
func (r *Reader) readRAID10(buf []byte, offset int64) (int, error) {
	stripe := r.cfg.StripeBytes
	pairs := int64(len(r.cfg.Disks) / 2)
	total := 0
	for total < len(buf) {
		logical := offset + int64(total)
		stripeIdx := logical / stripe
		stripeOff := logical % stripe
		pairIdx := stripeIdx % pairs
		// 在 pair 里挑一块可用盘
		var d disk.DiskReader
		if r.cfg.Disks[pairIdx*2] != nil {
			d = r.cfg.Disks[pairIdx*2]
		} else {
			d = r.cfg.Disks[pairIdx*2+1]
		}
		// pair 内的 stripe 序号
		diskStripeNo := stripeIdx / pairs
		diskOff := diskStripeNo*stripe + stripeOff

		want := stripe - stripeOff
		remain := int64(len(buf) - total)
		if want > remain {
			want = remain
		}
		got, err := d.ReadAt(buf[total:total+int(want)], diskOff)
		total += got
		if err != nil && err != io.EOF {
			return total, err
		}
		if got == 0 {
			break
		}
	}
	return total, nil
}

// ---------------- RAID 0 ----------------

func (r *Reader) readRAID0(buf []byte, offset int64) (int, error) {
	stripe := r.cfg.StripeBytes
	n := int64(len(r.cfg.Disks))
	total := 0
	for total < len(buf) {
		logical := offset + int64(total)
		stripeIdx := logical / stripe
		stripeOff := logical % stripe
		diskIdx := stripeIdx % n
		diskStripeNo := stripeIdx / n
		diskOff := diskStripeNo*stripe + stripeOff

		// 单次读不能跨条带边界
		want := stripe - stripeOff
		remain := int64(len(buf) - total)
		if want > remain {
			want = remain
		}
		got, err := r.cfg.Disks[diskIdx].ReadAt(buf[total:total+int(want)], diskOff)
		total += got
		if err != nil && err != io.EOF {
			return total, err
		}
		if got == 0 {
			break
		}
	}
	return total, nil
}

// ---------------- RAID 1 ----------------

func (r *Reader) readRAID1(buf []byte, offset int64) (int, error) {
	// 任一非 nil 盘都行；优先第一块
	for _, d := range r.cfg.Disks {
		if d == nil {
			continue
		}
		return d.ReadAt(buf, offset)
	}
	return 0, errors.New("RAID 1 没有可用盘")
}

// ---------------- RAID 5 ----------------

// readRAID5 按 left-symmetric 默认排列翻译。其它排列等需要时再补 switch。
func (r *Reader) readRAID5(buf []byte, offset int64) (int, error) {
	stripe := r.cfg.StripeBytes
	n := int64(len(r.cfg.Disks))
	dataPerRow := n - 1 // 一行有 N-1 个数据条带 + 1 个校验

	total := 0
	for total < len(buf) {
		logical := offset + int64(total)
		// 当前所在的"逻辑数据条带"编号
		logStripeIdx := logical / stripe
		stripeOff := logical % stripe
		// 哪一行 + 行内第几个数据列
		row := logStripeIdx / dataPerRow
		colInRow := logStripeIdx % dataPerRow

		// left-symmetric：parity 在第 (n - 1 - row%n) 列；数据列从 parity+1 开始环绕
		parityCol := (n - 1 - row%n + n) % n
		// 行内逻辑列 colInRow → 实际磁盘 idx：从 parityCol+1 开始 colInRow 步（环绕跳过 parity）
		diskIdx := (parityCol + 1 + colInRow) % n
		// 该列在该盘的物理 stripe 号 = row（每行每盘各一条带）
		diskOff := row*stripe + stripeOff

		want := stripe - stripeOff
		remain := int64(len(buf) - total)
		if want > remain {
			want = remain
		}

		// 读：如果目标盘存在直接读；缺失就用同行其它数据盘 + parity 重建
		var got int
		var err error
		if r.cfg.Disks[diskIdx] != nil {
			got, err = r.cfg.Disks[diskIdx].ReadAt(buf[total:total+int(want)], diskOff)
		} else {
			got, err = r.rebuildRAID5Row(buf[total:total+int(want)], row, colInRow, parityCol, diskOff)
		}
		total += got
		if err != nil && err != io.EOF {
			return total, err
		}
		if got == 0 {
			break
		}
	}
	return total, nil
}

// rebuildRAID5Row 用同一行其它盘 + 校验盘 XOR 重建出缺失盘的指定字节段。
// 当且仅当**只**缺一块盘（被请求那块）时调用；其它盘都必须存在。
//
// 算法：把行内所有"非缺失"的数据盘字节 + 校验盘字节全部 XOR 起来 = 缺失盘字节。
func (r *Reader) rebuildRAID5Row(out []byte, row int64, missingCol int64, parityCol int64, diskOff int64) (int, error) {
	n := int64(len(r.cfg.Disks))
	tmp := make([]byte, len(out))
	// 清零累加缓冲
	for i := range out {
		out[i] = 0
	}
	xorIn := func(d disk.DiskReader) error {
		got, err := d.ReadAt(tmp, diskOff)
		if err != nil && err != io.EOF {
			return err
		}
		for i := 0; i < got; i++ {
			out[i] ^= tmp[i]
		}
		return nil
	}

	// 数据盘（行内列号 0..dataPerRow-1，跳过 missingCol）
	for col := int64(0); col < n-1; col++ {
		if col == missingCol {
			continue
		}
		diskIdx := (parityCol + 1 + col) % n
		if r.cfg.Disks[diskIdx] == nil {
			return 0, fmt.Errorf("RAID 5 重建时另有盘缺失: disk[%d]", diskIdx)
		}
		if err := xorIn(r.cfg.Disks[diskIdx]); err != nil {
			return 0, err
		}
	}
	// 校验盘
	if r.cfg.Disks[parityCol] == nil {
		return 0, fmt.Errorf("RAID 5 重建时校验盘缺失: disk[%d]", parityCol)
	}
	if err := xorIn(r.cfg.Disks[parityCol]); err != nil {
		return 0, err
	}
	return len(out), nil
}

// 编译期断言 Reader 实现 disk.DiskReader
var _ disk.DiskReader = (*Reader)(nil)
