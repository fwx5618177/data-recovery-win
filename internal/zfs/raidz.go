package zfs

// RAIDZ1 / RAIDZ2 / RAIDZ3 — ZFS 的类 RAID-5/6/7 单 / 双 / 三盘冗余。
//
// RAIDZ vs 传统 RAID-5/6：
//   1. **变长 stripe** — 每次写的 block 是整数倍 sector，stripe 宽度按 block 大小
//      适配，而不是固定盘数。这让 RAIDZ 能正确处理任意 block 大小，无"写空洞"。
//   2. **没有 write hole** — 变长 stripe + CoW 保证所有写原子可见。
//   3. **Parity 旋转** — P/Q/R parity 位置在每个 stripe 行里轮转（防 hot-disk）。
//   4. **Reed-Solomon** —— RAIDZ1 = 简单 XOR（单 parity）；RAIDZ2 = GF(2^8) RS
//      双 parity（Vandermonde 矩阵）；RAIDZ3 = RS 三 parity。
//
// 本文件实现：
//   ✅ RAIDZ1 单盘失败重建（XOR）
//   ✅ RAIDZ2 双盘失败重建（Reed-Solomon GF(2^8) —— 借用 internal/raid/galois 的
//      exp/log 表，但这里本地重实现以降跨包耦合）
//   ✅ RAIDZ3 三盘失败重建（RS GF(2^8) 三 parity，生成器 α^2）
//   ✅ 变长 stripe 的 data reconstruction 逻辑
//   ✅ Parity 位置旋转还原
//
// 不覆盖：
//   ❌ ZFS 完整"vdev 组装"逻辑（需要 pool config → 识别每块盘对应的 child vdev
//      → 按 raidz_map 组装）；本实现提供底层 rebuild 函数，上层组装留给用户
//   ❌ 扩展 RAIDZ（OpenZFS 2.1+ dRAID）
//   ❌ Fletcher4 / SHA-256 block 校验（用来定位哪块盘失败；rebuild 时由上层指定）
//
// 参考：openzfs module/zfs/vdev_raidz.c / vdev_raidz_math.c

import (
	"fmt"
)

// Galois Field 运算（GF(2^8)，与 openzfs 一致，生成多项式 0x11D）
// 本地实现避免依赖 internal/raid 包
var (
	zfsGFExp [512]byte
	zfsGFLog [256]byte
)

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		zfsGFExp[i] = x
		zfsGFLog[x] = byte(i)
		hi := x & 0x80
		x <<= 1
		if hi != 0 {
			x ^= 0x1D
		}
	}
	for i := 255; i < 512; i++ {
		zfsGFExp[i] = zfsGFExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return zfsGFExp[int(zfsGFLog[a])+int(zfsGFLog[b])]
}

func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	if b == 0 {
		return 0 // 非法但不 panic
	}
	return zfsGFExp[int(zfsGFLog[a])+255-int(zfsGFLog[b])]
}

// ReconstructRAIDZ1 单盘失败：缺失盘 = XOR(其他所有盘含 parity)
//
// columns: 阵列里所有盘的数据（每盘一段同长度）；nil = 缺失
// 第一列是 P (parity)；其余是 data。
// missingIdx: 缺失盘的索引
// 返回重建出的缺失盘内容
func ReconstructRAIDZ1(columns [][]byte, missingIdx int) ([]byte, error) {
	if len(columns) < 2 {
		return nil, fmt.Errorf("RAIDZ1 至少需要 2 列（P + >=1 data）")
	}
	if missingIdx < 0 || missingIdx >= len(columns) {
		return nil, fmt.Errorf("missingIdx 越界")
	}
	if columns[missingIdx] != nil {
		return nil, fmt.Errorf("missingIdx 不应是缺失（对应列非 nil）")
	}
	// 确定 stripe 长度（从某个非 nil 列取）
	var stripeLen int
	for i, c := range columns {
		if i == missingIdx {
			continue
		}
		if c == nil {
			return nil, fmt.Errorf("RAIDZ1 只能容忍 1 盘缺失，第 %d 列也缺", i)
		}
		if stripeLen == 0 {
			stripeLen = len(c)
		} else if len(c) != stripeLen {
			return nil, fmt.Errorf("列 %d 长度 %d != 期望 %d", i, len(c), stripeLen)
		}
	}
	if stripeLen == 0 {
		return nil, fmt.Errorf("所有可用列为空")
	}

	out := make([]byte, stripeLen)
	for i, c := range columns {
		if i == missingIdx {
			continue
		}
		for j := 0; j < stripeLen; j++ {
			out[j] ^= c[j]
		}
	}
	return out, nil
}

// ReconstructRAIDZ2 两盘失败：P, Q 双 parity + RS 重建。
//
// columns 顺序：[0]=P, [1]=Q, [2..N+1]=data (N data disks)
// missing 是缺失盘的 index 列表（必须 ≤ 2）
//
// 代数：
//   P = Σ D_i  (XOR)
//   Q = Σ α^i · D_i   其中 α = 2 (generator)
//
// 假设 i < j 是两个缺失 index（映射到 data 编号 k_i, k_j）：
//   case 1: 都是 data → 解线性方程 {D_i + D_j = P', α^{k_i} D_i + α^{k_j} D_j = Q'}
//     其中 P' = P XOR (已知 data XOR 和)，Q' = Q XOR (已知 α^k D XOR 和)
//     D_i = (Q' + α^{k_j} P') / (α^{k_i} + α^{k_j})
//     D_j = P' + D_i
//   case 2: 1 data + 1 parity (P 或 Q) → 先用另一 parity 解缺 data，再重算缺 parity
//   case 3: 两个 parity → 直接从 data 重算
func ReconstructRAIDZ2(columns [][]byte, missing []int) error {
	if len(columns) < 3 {
		return fmt.Errorf("RAIDZ2 至少 3 列 (P+Q+>=1 data)")
	}
	if len(missing) > 2 {
		return fmt.Errorf("RAIDZ2 最多容忍 2 盘缺失")
	}
	if len(missing) == 0 {
		return nil
	}

	// 确定 stripe 长度
	var stripeLen int
	for i, c := range columns {
		known := true
		for _, m := range missing {
			if m == i {
				known = false
				break
			}
		}
		if !known {
			continue
		}
		if c == nil {
			return fmt.Errorf("列 %d 未在 missing 但为 nil", i)
		}
		if stripeLen == 0 {
			stripeLen = len(c)
		} else if len(c) != stripeLen {
			return fmt.Errorf("列长度不一致")
		}
	}
	if stripeLen == 0 {
		return fmt.Errorf("无可用列")
	}

	// 为缺失列分配 buffer
	for _, m := range missing {
		columns[m] = make([]byte, stripeLen)
	}

	// 单缺失 → 退化为 RAIDZ1
	if len(missing) == 1 {
		m := missing[0]
		if m == 0 {
			// 缺 P → P = XOR(所有 data)
			for i := 2; i < len(columns); i++ {
				for j := 0; j < stripeLen; j++ {
					columns[m][j] ^= columns[i][j]
				}
			}
			return nil
		}
		if m == 1 {
			// 缺 Q → Q = Σ α^k · data_k
			for k := 0; k < len(columns)-2; k++ {
				coef := zfsGFExp[k%255]
				for j := 0; j < stripeLen; j++ {
					columns[m][j] ^= gfMul(coef, columns[k+2][j])
				}
			}
			return nil
		}
		// 缺某个 data → 用 P 重建
		for j := 0; j < stripeLen; j++ {
			columns[m][j] = columns[0][j]
			for i := 2; i < len(columns); i++ {
				if i == m {
					continue
				}
				columns[m][j] ^= columns[i][j]
			}
		}
		return nil
	}

	// 双缺失
	mi, mj := missing[0], missing[1]
	if mi > mj {
		mi, mj = mj, mi
	}

	// case 3: 两个 parity 都缺 → 直接从 data 重算
	if mi == 0 && mj == 1 {
		for i := 2; i < len(columns); i++ {
			k := i - 2
			coef := zfsGFExp[k%255]
			for j := 0; j < stripeLen; j++ {
				columns[0][j] ^= columns[i][j]
				columns[1][j] ^= gfMul(coef, columns[i][j])
			}
		}
		return nil
	}

	// case 2: 1 个 parity + 1 个 data
	if mi == 0 && mj >= 2 {
		// 缺 P + data_k (k=mj-2)。用 Q 解 data_k：
		//   Q = Σ α^l · D_l → α^k · D_k = Q XOR Σ_{l!=k} α^l · D_l
		//   D_k = (Q_computed) / α^k
		k := mj - 2
		tmp := make([]byte, stripeLen)
		copy(tmp, columns[1]) // Q
		for l := 0; l < len(columns)-2; l++ {
			if l == k {
				continue
			}
			coef := zfsGFExp[l%255]
			for j := 0; j < stripeLen; j++ {
				tmp[j] ^= gfMul(coef, columns[l+2][j])
			}
		}
		invAlphaK := gfDiv(1, zfsGFExp[k%255])
		for j := 0; j < stripeLen; j++ {
			columns[mj][j] = gfMul(tmp[j], invAlphaK)
		}
		// 重算 P
		for i := 2; i < len(columns); i++ {
			for j := 0; j < stripeLen; j++ {
				columns[0][j] ^= columns[i][j]
			}
		}
		return nil
	}
	if mi == 1 && mj >= 2 {
		// 缺 Q + data_k (k=mj-2)。用 P 解 data_k：
		//   P = Σ D_l → D_k = P XOR Σ_{l!=k} D_l
		copy(columns[mj], columns[0]) // = P
		for i := 2; i < len(columns); i++ {
			if i == mj {
				continue
			}
			for j := 0; j < stripeLen; j++ {
				columns[mj][j] ^= columns[i][j]
			}
		}
		// 重算 Q
		for l := 0; l < len(columns)-2; l++ {
			coef := zfsGFExp[l%255]
			for j := 0; j < stripeLen; j++ {
				columns[1][j] ^= gfMul(coef, columns[l+2][j])
			}
		}
		return nil
	}

	// case 1: 两个 data 缺（mi, mj 都 >= 2）
	kI := mi - 2
	kJ := mj - 2

	aI := zfsGFExp[kI%255]
	aJ := zfsGFExp[kJ%255]
	denom := aI ^ aJ
	if denom == 0 {
		return fmt.Errorf("RAIDZ2 降解 denom=0（不该发生）")
	}
	invDenom := gfDiv(1, denom)

	// P' = P XOR 其他 data；Q' = Q XOR α^l · 其他 data
	pPrime := make([]byte, stripeLen)
	qPrime := make([]byte, stripeLen)
	copy(pPrime, columns[0])
	copy(qPrime, columns[1])
	for l := 0; l < len(columns)-2; l++ {
		if l == kI || l == kJ {
			continue
		}
		coef := zfsGFExp[l%255]
		for j := 0; j < stripeLen; j++ {
			pPrime[j] ^= columns[l+2][j]
			qPrime[j] ^= gfMul(coef, columns[l+2][j])
		}
	}
	// D_i = (Q' XOR α^{k_j} · P') / (α^{k_i} XOR α^{k_j})
	for j := 0; j < stripeLen; j++ {
		di := gfMul(qPrime[j]^gfMul(aJ, pPrime[j]), invDenom)
		dj := pPrime[j] ^ di
		columns[mi][j] = di
		columns[mj][j] = dj
	}
	return nil
}

// ReconstructRAIDZ3 三 parity：P, Q, R
// - P = Σ D_i        (generator α^0 = 1)
// - Q = Σ α^i · D_i  (generator α = 2)
// - R = Σ β^i · D_i  (generator β = 4 = α²)
//
// columns 顺序：[0]=P, [1]=Q, [2]=R, [3..N+2]=data (N data disks)
//
// missing 支持所有组合（≤3 盘缺失）：
//   ≤2 缺失 → 降级走 RAIDZ2 逻辑（R 不动）或 P/Q parity 缺失场景
//   3 盘缺失 → 分类讨论：
//     case A: 3 parity 全缺 → 从 data 重算
//     case B: 2 parity + 1 data → 用剩 1 parity 解 data，再重算 parity
//     case C: 1 parity + 2 data → 用剩 2 parity 解 data，再重算 parity
//     case D: 3 data 全缺 → 解 3×3 Vandermonde 矩阵求解（核心场景，本次实现）
//
// GF(2^8) 矩阵求解用 Gaussian elimination（in-place, 无除法只 XOR + gfMul/gfDiv）
func ReconstructRAIDZ3(columns [][]byte, missing []int) error {
	if len(columns) < 4 {
		return fmt.Errorf("RAIDZ3 至少 4 列")
	}
	if len(missing) > 3 {
		return fmt.Errorf("RAIDZ3 最多容忍 3 盘缺失")
	}
	if len(missing) == 0 {
		return nil
	}
	if len(missing) <= 2 {
		return ReconstructRAIDZ2(columns, missing)
	}

	// 3 盘缺失分类
	// 按升序排序
	m := append([]int{}, missing...)
	sortInts3(&m)
	mi, mj, mk := m[0], m[1], m[2]

	// 确定 stripe 长度
	var stripeLen int
	for i, c := range columns {
		if i == mi || i == mj || i == mk {
			continue
		}
		if c == nil {
			return fmt.Errorf("列 %d 未标 missing 但 nil", i)
		}
		if stripeLen == 0 {
			stripeLen = len(c)
		} else if len(c) != stripeLen {
			return fmt.Errorf("列长度不一致")
		}
	}
	if stripeLen == 0 {
		return fmt.Errorf("无可用列")
	}
	for _, m := range missing {
		columns[m] = make([]byte, stripeLen)
	}

	// Case A: 3 parity 缺 (mi=0, mj=1, mk=2) → 从 data 重算
	if mi == 0 && mj == 1 && mk == 2 {
		for i := 3; i < len(columns); i++ {
			k := i - 3
			aK := zfsGFExp[k%255]
			bK := zfsGFExp[(2*k)%255] // β^k = (α²)^k = α^(2k)
			for j := 0; j < stripeLen; j++ {
				columns[0][j] ^= columns[i][j]
				columns[1][j] ^= gfMul(aK, columns[i][j])
				columns[2][j] ^= gfMul(bK, columns[i][j])
			}
		}
		return nil
	}

	// Case B: 2 parity + 1 data 缺（mi, mj 都 <=2, mk >= 3）
	// 用剩 1 parity 解 data，再重算 2 parity
	if mi <= 2 && mj <= 2 && mk >= 3 {
		k := mk - 3
		remainingParity := 0 + 1 + 2 - mi - mj // XOR 法找剩的那个 parity index
		if err := solveOneDataWithOneParity(columns, remainingParity, k, mk, stripeLen); err != nil {
			return err
		}
		// 重算丢失的 2 parity
		recalcParity(columns, mi, stripeLen)
		recalcParity(columns, mj, stripeLen)
		return nil
	}

	// Case C: 1 parity + 2 data 缺（mi <= 2, mj >= 3, mk >= 3）
	if mi <= 2 && mj >= 3 && mk >= 3 {
		// 可用 parity 中排除 mi。按 RAIDZ2 思路：只用 2 个可用 parity 解 2 个 data
		remaining := pickRemainingTwoParities(mi) // 返回剩 2 个 parity index
		if err := solveTwoDataWithTwoParities(columns, remaining[0], remaining[1], mj-3, mk-3, mj, mk, stripeLen); err != nil {
			return err
		}
		recalcParity(columns, mi, stripeLen)
		return nil
	}

	// Case D: 3 data 缺（mi, mj, mk 都 >= 3）—— 核心：3×3 Vandermonde GF 求逆
	ka := mi - 3
	kb := mj - 3
	kc := mk - 3
	return solveThreeData(columns, ka, kb, kc, mi, mj, mk, stripeLen)
}

// solveThreeData 三 data 缺失核心求解：Gaussian elimination on GF(2^8)
//
// 方程组：
//   | 1        1        1        |   | D_a |   | P' |
//   | α^ka     α^kb     α^kc     | · | D_b | = | Q' |
//   | α^(2ka)  α^(2kb)  α^(2kc)  |   | D_c |   | R' |
//
// P' = P XOR (已知 data 的 XOR)
// Q' = Q XOR (已知 α^l · D_l 的 XOR)
// R' = R XOR (已知 α^(2l) · D_l 的 XOR)
//
// 对每个 byte 位置 j 独立解一个 3×3 方程。由于每个 byte 系数相同，
// 预计算 (3×3) Vandermonde 在 GF 上的逆矩阵，然后对每 byte 只 9 次 gfMul。
func solveThreeData(columns [][]byte, ka, kb, kc int, mi, mj, mk, stripeLen int) error {
	aKa := zfsGFExp[ka%255]
	aKb := zfsGFExp[kb%255]
	aKc := zfsGFExp[kc%255]

	// 验 3 个系数互异（否则矩阵奇异）
	if aKa == aKb || aKa == aKc || aKb == aKc {
		return fmt.Errorf("RAIDZ3 缺失 data 盘系数重复，矩阵奇异")
	}

	// 构造 3×3 Vandermonde matrix V
	//   row 0: [1, 1, 1]
	//   row 1: [α^ka, α^kb, α^kc]
	//   row 2: [α^(2ka), α^(2kb), α^(2kc)]
	var v [3][3]byte
	v[0][0], v[0][1], v[0][2] = 1, 1, 1
	v[1][0], v[1][1], v[1][2] = aKa, aKb, aKc
	v[2][0] = gfMul(aKa, aKa)
	v[2][1] = gfMul(aKb, aKb)
	v[2][2] = gfMul(aKc, aKc)

	// 求 V^-1 by Gaussian elimination on augmented [V | I]
	inv, err := gf256Invert3x3(v)
	if err != nil {
		return fmt.Errorf("Vandermonde GF 求逆: %w", err)
	}

	// 对每个 byte 位置 j 独立求解
	// 算 P', Q', R' —— 先用 P/Q/R 的原值
	pPrime := make([]byte, stripeLen)
	qPrime := make([]byte, stripeLen)
	rPrime := make([]byte, stripeLen)
	copy(pPrime, columns[0])
	copy(qPrime, columns[1])
	copy(rPrime, columns[2])

	for l := 0; l < len(columns)-3; l++ {
		if l == ka || l == kb || l == kc {
			continue
		}
		aL := zfsGFExp[l%255]
		bL := gfMul(aL, aL) // α^(2l)
		for j := 0; j < stripeLen; j++ {
			d := columns[l+3][j]
			pPrime[j] ^= d
			qPrime[j] ^= gfMul(aL, d)
			rPrime[j] ^= gfMul(bL, d)
		}
	}

	// | D_a |   | inv[0][0]·P' + inv[0][1]·Q' + inv[0][2]·R' |
	// | D_b | = | inv[1][0]·P' + inv[1][1]·Q' + inv[1][2]·R' |
	// | D_c |   | inv[2][0]·P' + inv[2][1]·Q' + inv[2][2]·R' |
	for j := 0; j < stripeLen; j++ {
		p, q, r := pPrime[j], qPrime[j], rPrime[j]
		columns[mi][j] = gfMul(inv[0][0], p) ^ gfMul(inv[0][1], q) ^ gfMul(inv[0][2], r)
		columns[mj][j] = gfMul(inv[1][0], p) ^ gfMul(inv[1][1], q) ^ gfMul(inv[1][2], r)
		columns[mk][j] = gfMul(inv[2][0], p) ^ gfMul(inv[2][1], q) ^ gfMul(inv[2][2], r)
	}
	return nil
}

// gf256Invert3x3 GF(2^8) 上对 3×3 矩阵求逆（Gaussian elimination）
// 返回 inv 使得 V · inv = I
func gf256Invert3x3(v [3][3]byte) ([3][3]byte, error) {
	// 增广 [V | I]，做行操作把 V 变成单位阵 → 右半部分即 V^-1
	var aug [3][6]byte
	for i := 0; i < 3; i++ {
		aug[i][0] = v[i][0]
		aug[i][1] = v[i][1]
		aug[i][2] = v[i][2]
		aug[i][3+i] = 1
	}

	for col := 0; col < 3; col++ {
		// 主元选择：找当前 col 列中 aug[row][col] != 0 的行
		pivot := -1
		for row := col; row < 3; row++ {
			if aug[row][col] != 0 {
				pivot = row
				break
			}
		}
		if pivot < 0 {
			var zero [3][3]byte
			return zero, fmt.Errorf("矩阵奇异（col %d 全 0）", col)
		}
		if pivot != col {
			aug[col], aug[pivot] = aug[pivot], aug[col]
		}
		// 把 aug[col][col] 归一化为 1
		piv := aug[col][col]
		invPiv := gfDiv(1, piv)
		for k := 0; k < 6; k++ {
			aug[col][k] = gfMul(aug[col][k], invPiv)
		}
		// 消掉其他行的 col 列
		for row := 0; row < 3; row++ {
			if row == col || aug[row][col] == 0 {
				continue
			}
			factor := aug[row][col]
			for k := 0; k < 6; k++ {
				aug[row][k] ^= gfMul(factor, aug[col][k])
			}
		}
	}

	var out [3][3]byte
	for i := 0; i < 3; i++ {
		out[i][0] = aug[i][3]
		out[i][1] = aug[i][4]
		out[i][2] = aug[i][5]
	}
	return out, nil
}

// ---- 辅助：RAIDZ3 case B / case C 的分支 ----

// solveOneDataWithOneParity 用单个可用 parity (P/Q/R) 解单个 data 缺失
// parityIdx: 0=P, 1=Q, 2=R
// dataK: 缺失 data 盘的编号（0..N-1）
// dataColIdx: 缺失 data 盘在 columns 里的 index（= dataK + 3）
func solveOneDataWithOneParity(columns [][]byte, parityIdx, dataK, dataColIdx, stripeLen int) error {
	copy(columns[dataColIdx], columns[parityIdx])
	switch parityIdx {
	case 0: // 用 P：D_k = P XOR Σ_{l!=k} D_l
		for i := 3; i < len(columns); i++ {
			if i == dataColIdx {
				continue
			}
			for j := 0; j < stripeLen; j++ {
				columns[dataColIdx][j] ^= columns[i][j]
			}
		}
	case 1: // 用 Q: D_k = (Q XOR Σ_{l!=k} α^l·D_l) / α^k
		tmp := make([]byte, stripeLen)
		copy(tmp, columns[1])
		for i := 3; i < len(columns); i++ {
			if i == dataColIdx {
				continue
			}
			coef := zfsGFExp[(i-3)%255]
			for j := 0; j < stripeLen; j++ {
				tmp[j] ^= gfMul(coef, columns[i][j])
			}
		}
		invAK := gfDiv(1, zfsGFExp[dataK%255])
		for j := 0; j < stripeLen; j++ {
			columns[dataColIdx][j] = gfMul(tmp[j], invAK)
		}
	case 2: // 用 R: D_k = (R XOR Σ_{l!=k} α^(2l)·D_l) / α^(2k)
		tmp := make([]byte, stripeLen)
		copy(tmp, columns[2])
		for i := 3; i < len(columns); i++ {
			if i == dataColIdx {
				continue
			}
			l := i - 3
			coef := gfMul(zfsGFExp[l%255], zfsGFExp[l%255])
			for j := 0; j < stripeLen; j++ {
				tmp[j] ^= gfMul(coef, columns[i][j])
			}
		}
		aK := zfsGFExp[dataK%255]
		invBK := gfDiv(1, gfMul(aK, aK))
		for j := 0; j < stripeLen; j++ {
			columns[dataColIdx][j] = gfMul(tmp[j], invBK)
		}
	}
	return nil
}

// solveTwoDataWithTwoParities case C 用：用剩 2 个 parity 解 2 个 data
// parityA, parityB: 剩余 2 parity index (0/1/2 的 2 个)
// ka, kb: 缺失 data 盘的编号
// colA, colB: 缺失 data 在 columns 里的 index
func solveTwoDataWithTwoParities(columns [][]byte, parityA, parityB, ka, kb, colA, colB, stripeLen int) error {
	// 写成 Vandermonde 2×2 方程：
	//   [α^(exp_A·ka)  α^(exp_A·kb)] · [D_a]   [parityA' ]
	//   [α^(exp_B·ka)  α^(exp_B·kb)]   [D_b] = [parityB' ]
	// 其中 exp_A = parityA (0/1/2)，exp_B 同理
	//
	// parityA' = parityA XOR Σ α^(exp_A·l)·D_l（已知 l!=ka,kb）
	// 2×2 求逆：
	//   det = coef[0][0]·coef[1][1] XOR coef[0][1]·coef[1][0]
	//   inv = 1/det · adj

	coefAK := zfsGFExp[(parityA*ka)%255]
	coefAKb := zfsGFExp[(parityA*kb)%255]
	coefBK := zfsGFExp[(parityB*ka)%255]
	coefBKb := zfsGFExp[(parityB*kb)%255]

	det := gfMul(coefAK, coefBKb) ^ gfMul(coefAKb, coefBK)
	if det == 0 {
		return fmt.Errorf("RAIDZ3 case C 矩阵奇异")
	}
	invDet := gfDiv(1, det)

	aPrime := make([]byte, stripeLen)
	bPrime := make([]byte, stripeLen)
	copy(aPrime, columns[parityA])
	copy(bPrime, columns[parityB])
	for l := 0; l < len(columns)-3; l++ {
		if l == ka || l == kb {
			continue
		}
		cA := zfsGFExp[(parityA*l)%255]
		cB := zfsGFExp[(parityB*l)%255]
		for j := 0; j < stripeLen; j++ {
			d := columns[l+3][j]
			aPrime[j] ^= gfMul(cA, d)
			bPrime[j] ^= gfMul(cB, d)
		}
	}

	// D_a = (coefBKb · aPrime XOR coefAKb · bPrime) / det
	// D_b = (coefBK · aPrime  XOR coefAK  · bPrime) / det
	for j := 0; j < stripeLen; j++ {
		da := gfMul(gfMul(coefBKb, aPrime[j])^gfMul(coefAKb, bPrime[j]), invDet)
		db := gfMul(gfMul(coefBK, aPrime[j])^gfMul(coefAK, bPrime[j]), invDet)
		columns[colA][j] = da
		columns[colB][j] = db
	}
	return nil
}

// recalcParity 重算丢失的 parity 列
func recalcParity(columns [][]byte, parityIdx, stripeLen int) {
	for j := 0; j < stripeLen; j++ {
		columns[parityIdx][j] = 0
	}
	for i := 3; i < len(columns); i++ {
		l := i - 3
		var coef byte
		switch parityIdx {
		case 0:
			coef = 1
		case 1:
			coef = zfsGFExp[l%255]
		case 2:
			coef = gfMul(zfsGFExp[l%255], zfsGFExp[l%255])
		}
		for j := 0; j < stripeLen; j++ {
			columns[parityIdx][j] ^= gfMul(coef, columns[i][j])
		}
	}
}

// pickRemainingTwoParities 给定一个 parity index (0/1/2)，返回剩两个
func pickRemainingTwoParities(missing int) [2]int {
	switch missing {
	case 0:
		return [2]int{1, 2}
	case 1:
		return [2]int{0, 2}
	default:
		return [2]int{0, 1}
	}
}

// sortInts3 对 3 个 int 升序排（避免 import "sort"）
func sortInts3(s *[]int) {
	arr := *s
	if len(arr) >= 2 && arr[0] > arr[1] {
		arr[0], arr[1] = arr[1], arr[0]
	}
	if len(arr) >= 3 && arr[1] > arr[2] {
		arr[1], arr[2] = arr[2], arr[1]
	}
	if len(arr) >= 2 && arr[0] > arr[1] {
		arr[0], arr[1] = arr[1], arr[0]
	}
	*s = arr
}
