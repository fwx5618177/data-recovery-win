package veracrypt

// ============================================================================
// VeraCrypt / TrueCrypt 解锁链：密码 → header_key → 解头 → master_key → DecryptedReader
//
// 性能优化点：
//   1. 一次读 64KB 卷头区到内存，避免每次 hash 派生时重读盘
//   2. 每个 (algo, isTC) 组合派生独立 header_key（PBKDF2 ~ 1-3 秒/次）
//   3. PBKDF2 输出固定 192 字节，足够 cascade（cascade 实际还没实现，留接口）
//   4. AES-XTS 解密整个 448 字节 encrypted block 当 1 个 sector（index=0）
//   5. 一旦匹配 signature + CRC，立即停止枚举
//
// 当前覆盖：
//   - VeraCrypt: SHA-512 + SHA-256 + RIPEMD-160（覆盖 ~95% VC 用户）
//   - TrueCrypt: SHA-512 + RIPEMD-160（覆盖 ~95% TC 用户）
//   - Cipher: AES-XTS-256 + Twofish-XTS-256（覆盖 ~90% 用户；Serpent + 多 cipher
//     cascade 仍未实现 —— Serpent 在 Go 标准库 / x/crypto 都没有，需要自己 port
//     800+ 行的 reference 实现，留 TODO）
//
// 一次成功解锁的最坏耗时：3 hash × 2 (VC/TC) × 2 cipher = 12 次 PBKDF2 ≈ 20-30 秒。
// 但同一 hash 下不同 cipher 共用 PBKDF2 输出（KDF 与 cipher 无关）→ 实际只跑
// 6 次 PBKDF2 + 6 次 cipher 试解。UI 上显示"正在尝试 X / 12"进度文本。
// ============================================================================

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"data-recovery/internal/disk"
	"data-recovery/internal/luks"

	//lint:ignore SA1019 legacy VC compatibility
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xts"
)

// ErrWrongPassword 密码错或无支持算法命中
var ErrWrongPassword = errors.New("VC: 密码错误或卷使用了本工具不支持的 cipher / hash")

// UnlockedVolume 是 OpenAndUnlock 的返回结果
type UnlockedVolume struct {
	Reader        *luks.DecryptedReader
	IsTrueCrypt   bool   // true = "TRUE" 容器（老 TC 7.x）
	Header        *VolumeHeader
	HashAlgorithm string // 命中的 PBKDF2 hash 名称（"sha512" 等）
	Cipher        string // 命中的 cipher 描述（"aes-xts"）
	MasterKey     []byte // 完整 master key 区副本（Close 后清零）
}

// Close 抹掉 master key
func (u *UnlockedVolume) Close() error {
	for i := range u.MasterKey {
		u.MasterKey[i] = 0
	}
	u.MasterKey = nil
	return nil
}

// UnlockProgress 是密码派生过程中的回调（每尝试一种 hash 触发一次）
type UnlockProgress func(triedAlgos int, totalAlgos int, currentAlgo string)

// OpenAndUnlock 用密码尝试解锁 VC/TC 卷（PIM=0，走默认 iter）。
//
// reader 必须已 Open()；volStart 是卷在 reader 上的字节起点（整盘容器 = 0）。
// progress 可以为 nil；用于 UI 显示"正在尝试 SHA-512…"
//
// 算法枚举顺序按 cryptsetup-veracrypt / VeraCrypt 客户端的真实命中频率排序，
// 让最常用的 SHA-512+VC 最先被试到。
func OpenAndUnlock(reader disk.DiskReader, volStart int64, password string, progress UnlockProgress) (*UnlockedVolume, error) {
	return OpenAndUnlockWithPIM(reader, volStart, password, 0, progress)
}

// OpenAndUnlockSystemEncryption 解锁 VeraCrypt 系统加密卷（Windows 全盘加密 boot 盘）。
//
// 与容器卷的关键差异：
//   1. 卷头不在 offset 0 而在 offset 31744（partition 内 sector 62）
//   2. KDF iter 用系统加密公式（IterationsForPIMSystem）：SHA 系列固定 200000，
//      RIPEMD = pim*2048（PIM=0 → 1000）；boot loader KDF 时间预算硬约束
//   3. 加密区从 sector 256 (= 131072) 起；boot loader 区 [0, 31744) 永远不加密
//
// partitionStart 是系统加密分区在 reader 上的字节起点（典型整盘 = 0）。
// pim == 0 走默认 SHA iter (200000)；> 0 时仅影响 RIPEMD（VC 设计如此）。
func OpenAndUnlockSystemEncryption(reader disk.DiskReader, partitionStart int64, password string, pim int, progress UnlockProgress) (*UnlockedVolume, error) {
	return openAndUnlockInternal(reader, partitionStart, password, pim, progress, true)
}

// OpenAndUnlockWithPIM 同 OpenAndUnlock，但允许指定 PIM (Personal Iterations
// Multiplier)。VeraCrypt 高级用户在创建容器时可指定 PIM 调整 KDF 强度，必须
// 知道 PIM 才能解开。
//
// pim == 0 等价于 OpenAndUnlock；pim > 0 时按 IterationsForPIM 公式算 iter。
//
// 注意：用 PIM 创建的卷只能用同一个 PIM 解开 —— PIM 错就跟密码错一样
// 表现为 ErrWrongPassword。
func OpenAndUnlockWithPIM(reader disk.DiskReader, volStart int64, password string, pim int, progress UnlockProgress) (*UnlockedVolume, error) {
	return openAndUnlockInternal(reader, volStart, password, pim, progress, false)
}

// openAndUnlockInternal 是容器卷与系统加密卷共用的解锁实现。
//
// isSystemEncryption 切换：
//   - header offset：0 vs SystemEncryptionHeaderOffset (31744)
//   - KDF iter：IterationsForPIM vs IterationsForPIMSystem
//   - PayloadOffset 解释：容器路径仍按 hdr.PayloadOffset，系统路径走 boot loader
//     之外的固定 sector 256 起点
func openAndUnlockInternal(reader disk.DiskReader, volStart int64, password string, pim int, progress UnlockProgress, isSystemEncryption bool) (*UnlockedVolume, error) {
	if reader == nil {
		return nil, errors.New("VC: reader 为 nil")
	}
	if password == "" {
		return nil, errors.New("VC: 密码为空")
	}
	if pim < 0 {
		return nil, fmt.Errorf("VC: PIM 必须 >= 0, got %d", pim)
	}

	// 卷头偏移：容器在 0；系统加密在 31744（partition sector 62）
	headerOff := volStart
	if isSystemEncryption {
		headerOff = volStart + SystemEncryptionHeaderOffset
	}
	// 读 512 字节卷头（salt + encrypted block）
	headerBuf := make([]byte, VolumeHeaderTotalSize)
	if _, err := reader.ReadAt(headerBuf, headerOff); err != nil && err != io.EOF {
		return nil, fmt.Errorf("VC: 读卷头: %w", err)
	}

	salt := headerBuf[:SaltSize]
	encHeader := headerBuf[SaltSize:VolumeHeaderTotalSize]

	hashes := SupportedHashes()
	ciphers := supportedCiphers()
	// 枚举顺序：VC（500K iter）→ TC（1K iter）；先试 VC 因为现代用户绝大多数用 VC
	// PIM 模式只对 VC 生效（TC 没有 PIM）；pim>0 时跳过 TC cases
	// 系统加密：boot loader 不可能写入 TC 头部，跳过 TC 路径
	cases := make([]unlockCase, 0, len(hashes)*2)
	for _, h := range hashes {
		cases = append(cases, unlockCase{
			hash: h, isTrueCrypt: false, pim: pim,
			isSystemEncryption: isSystemEncryption,
		})
	}
	if pim == 0 && !isSystemEncryption {
		for _, h := range hashes {
			// TC 不支持 SHA-256 / Streebog；这里只试 SHA-512 + RIPEMD-160
			if h.Name == "sha256" {
				continue
			}
			cases = append(cases, unlockCase{hash: h, isTrueCrypt: true, pim: 0})
		}
	}

	return parallelUnlock(reader, volStart, salt, encHeader, password, cases, ciphers, progress, isSystemEncryption)
}

// parallelUnlock 并发跑所有 (hash×cipher) 组合，第一个成功者即返回。
//
// 性能模型：
//   - 总 PBKDF2 次数 = len(cases)（同 hash 不同 cipher 共用输出）
//   - 每次 PBKDF2: 500K iter SHA-512 ≈ 1-3s on modern CPU
//   - 串行最坏 = len(cases) × 3s ≈ 18s
//   - 并发上界 = max(per-PBKDF2) ≈ 3s（但需 ≥ len(cases) 核心数才能完全并行）
//
// goroutine 数：min(len(cases), runtime.NumCPU())。N>NumCPU 反而拖慢（GC + 上下文切换）。
//
// 一旦任意 worker 命中，通过 ctx.Cancel 让其它 worker 在下个 PBKDF2 yield 点放弃。
// 但 PBKDF2 本身没有 cancellation 钩子，所以正在跑的 worker 必须跑完才退出 ——
// "命中后立刻返回结果给调用方"是性能正确的（不等其它 worker），
// 内存只是几个 192B header_key 副本，无害。
func parallelUnlock(reader disk.DiskReader, volStart int64, salt, encHeader []byte, password string, cases []unlockCase, ciphers []cipherSpec, progress UnlockProgress, isSystemEncryption bool) (*UnlockedVolume, error) {
	if len(cases) == 0 {
		return nil, ErrWrongPassword
	}
	concurrency := runtime.NumCPU()
	if concurrency > len(cases) {
		concurrency = len(cases)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	totalAttempts := len(cases) * len(ciphers)
	jobs := make(chan unlockCase, len(cases))
	for _, c := range cases {
		jobs <- c
	}
	close(jobs)

	type result struct {
		uv *UnlockedVolume
	}
	results := make(chan result, concurrency)

	var (
		mu          sync.Mutex
		attemptDone int
		stopped     bool
	)
	emitProgress := func(label string) {
		if progress == nil {
			return
		}
		mu.Lock()
		attemptDone++
		n := attemptDone
		mu.Unlock()
		progress(n, totalAttempts, label)
	}
	shouldStop := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return stopped
	}
	markStopped := func() {
		mu.Lock()
		stopped = true
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if shouldStop() {
					return
				}
				var iter int
				switch {
				case c.isTrueCrypt:
					iter = IterationsFor(true, c.hash.Name)
				case c.isSystemEncryption:
					// 系统加密 KDF 公式：SHA 系列固定 200000；RIPEMD = pim*2048（PIM=0 → 1000）
					iter = IterationsForPIMSystem(c.hash.Name, c.pim, true)
				case c.pim > 0:
					iter = IterationsForPIM(c.hash.Name, c.pim)
				default:
					iter = IterationsFor(false, c.hash.Name)
				}
				headerKeyMaterial := DeriveHeaderKey([]byte(password), salt, iter, c.hash.NewFn)
				if len(headerKeyMaterial) < 64 {
					continue
				}
				for _, cs := range ciphers {
					if shouldStop() {
						return
					}
					label := fmt.Sprintf("%s/%s/%s", boolToVCTC(c.isTrueCrypt), c.hash.Name, cs.Name)
					if c.pim > 0 {
						label = fmt.Sprintf("%s (PIM=%d)", label, c.pim)
					}
					emitProgress(label)
					uv := tryUnlockWithCipher(reader, volStart, encHeader, headerKeyMaterial, c, cs)
					if uv != nil {
						markStopped()
						results <- result{uv: uv}
						return
					}
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.uv != nil {
			return r.uv, nil
		}
	}
	return nil, ErrWrongPassword
}

type unlockCase struct {
	hash               HashSpec
	isTrueCrypt        bool
	pim                int  // 0 = 默认 iter；>0 = 按 IterationsForPIM 公式
	isSystemEncryption bool // VC 系统加密分支（不同 KDF 公式 + 卷头偏移 31744）
}

// cipherSpec 描述一个 VC 支持的 cipher 配置。
//
//   - Single cipher：Factories = [factory]，KeyBytes = 64
//   - 2-cipher cascade：Factories = [first-encrypt, second-encrypt]，KeyBytes = 128
//     名字 "AES-Twofish" 意为加密顺序 AES→Twofish（先 AES 再 Twofish），
//     解密顺序则反过来 Twofish→AES。
//
// Key 布局（按 *加密* 顺序）：keyMaterial[0:64] 给 Factories[0]，[64:128] 给 [1]，依次类推。
// 解密时 tryUnlockWithCipher 按 reversed(Factories) 跑。
type cipherSpec struct {
	Name      string
	Factories []func(key []byte) (cipher.Block, error)
	KeyBytes  int
}

func aesFactory(k []byte) (cipher.Block, error)     { return aes.NewCipher(k) }
func twofishFactory(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }

// supportedCiphers 返回我们解头部时枚举的 cipher 集合，按真实命中频率排序。
//
// 覆盖：
//   - AES-XTS（80% 用户）
//   - Twofish-XTS（5%）
//   - AES-Twofish cascade（5%；VC 默认 cascade 选项）
//
// 没覆盖：Serpent、Camellia、Kuznyechik、3-cipher cascade —— Serpent 没现成
// Go impl，其它更冷门。
func supportedCiphers() []cipherSpec {
	return []cipherSpec{
		{
			Name:      "aes",
			Factories: []func([]byte) (cipher.Block, error){aesFactory},
			KeyBytes:  64,
		},
		{
			Name:      "twofish",
			Factories: []func([]byte) (cipher.Block, error){twofishFactory},
			KeyBytes:  64,
		},
		{
			// 2-cipher cascade "AES-Twofish"：加密顺序 pt→AES→Twofish→ct
			// Factories 按加密顺序：[AES, Twofish]
			// 解密时 tryUnlockWithCipher 自动逆序遍历
			Name:      "aes-twofish",
			Factories: []func([]byte) (cipher.Block, error){aesFactory, twofishFactory},
			KeyBytes:  128,
		},
	}
}

func boolToVCTC(isTC bool) string {
	if isTC {
		return "TC"
	}
	return "VC"
}

// tryUnlockWithCipher 用给定的 (hash 派生出的 keyMaterial, cipher) 试解 header。
// 失败（signature/CRC 不匹配，或 cipher 装配失败）返回 nil；上层接着试下一个组合。
//
// 对 cascade cipher：按 cs.Factories 顺序逐层解密 header（每层用 keyMaterial
// 的 64B 段）。这样能解开用 cascade 加密的 VC 卷。
func tryUnlockWithCipher(reader disk.DiskReader, volStart int64, encHeader, headerKeyMaterial []byte, c unlockCase, cs cipherSpec) *UnlockedVolume {
	if len(headerKeyMaterial) < cs.KeyBytes {
		return nil
	}
	plain := make([]byte, EncryptedHeaderSize)
	copy(plain, encHeader)
	// 逐层解密（cascade）：Factories 按 *加密* 顺序，所以解密 reverse 遍历。
	// keyOff 跟 Factories 索引一致（Factories[i] 用 keyMaterial[i*64:(i+1)*64]）。
	for i := len(cs.Factories) - 1; i >= 0; i-- {
		factory := cs.Factories[i]
		keyOff := i * 64
		hkXTS, err := xts.NewCipher(factory, headerKeyMaterial[keyOff:keyOff+64])
		if err != nil {
			return nil
		}
		// VeraCrypt 用 sector_idx=0 加密整个 448B 块当成一个 data unit
		hkXTS.Decrypt(plain, plain, 0)
	}

	hdr, err := ParseDecryptedHeader(plain)
	if err != nil {
		return nil
	}

	// 解锁成功 → 装数据区 cipher（同 cipherSpec 再起实例，用 master key 区）
	if len(hdr.MasterKey) < cs.KeyBytes {
		return nil
	}
	dataCipher, err := buildDataCipher(cs.Name, hdr.MasterKey)
	if err != nil {
		return nil
	}

	// VC 数据区 sector_index = byte_offset_in_volume / SECTOR_SIZE
	ivBase := hdr.PayloadOffset / uint64(hdr.SectorSize)
	dr, err := luks.NewDecryptedReader(luks.DecryptedReaderConfig{
		Underlying:   reader,
		Cipher:       dataCipher,
		PayloadOff:   volStart + int64(hdr.PayloadOffset),
		PayloadSize:  int64(hdr.PayloadSize),
		IVBase:       ivBase,
		DevicePath:   fmt.Sprintf("vc-decrypted://%s", reader.DevicePath()),
		CacheSectors: 8192,
	})
	if err != nil {
		return nil
	}
	return &UnlockedVolume{
		Reader:        dr,
		IsTrueCrypt:   hdr.IsTrueCrypt,
		Header:        hdr,
		HashAlgorithm: c.hash.Name,
		Cipher:        cs.Name + "-xts",
		MasterKey:     append([]byte{}, hdr.MasterKey...),
	}
}
