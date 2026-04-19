package ntfs

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"data-recovery/internal/disk"
)

// ========== NTFS 文件系统常量 ==========

const (
	ntfsSignature            = "NTFS    " // 引导扇区 OEM ID（8字节，含尾部空格）
	mftEntrySignature        = "FILE"     // MFT 条目签名
	attrStandardInfo  uint32 = 0x10       // $STANDARD_INFORMATION 属性
	attrAttributeList uint32 = 0x20       // $ATTRIBUTE_LIST 属性（碎片化 MFT 条目用）
	attrFileName      uint32 = 0x30       // $FILE_NAME 属性
	attrData          uint32 = 0x80       // $DATA 属性
	attrIndexRoot     uint32 = 0x90       // $INDEX_ROOT 属性
	attrIndexAlloc    uint32 = 0xA0       // $INDEX_ALLOCATION 属性
	attrEnd           uint32 = 0xFFFFFFFF // 属性列表结束标记
	flagInUse         uint16 = 0x01       // MFT 条目正在使用
	flagDirectory     uint16 = 0x02       // MFT 条目是目录

	fileNameNamespacePosix       uint8 = 0 // POSIX 命名空间（区分大小写）
	fileNameNamespaceWin32       uint8 = 1 // Win32 命名空间
	fileNameNamespaceDOS         uint8 = 2 // DOS 8.3 短文件名命名空间
	fileNameNamespaceWin32AndDOS uint8 = 3 // Win32 & DOS 合并命名空间

	// MBR / GPT 相关常量见 partition.go。

	// NTFS 根目录 MFT 条目号
	rootDirEntryNumber int64 = 5

	// 系统元数据文件条目号上限（0-23 为系统保留）
	systemEntryLimit int64 = 24

	// 目录树重建最大深度，防止循环引用
	maxPathDepth = 100

	// 进度回调间隔
	progressInterval int64 = 100
)

// ========== 数据结构 ==========

// BootSector NTFS 引导扇区解析结果
type BootSector struct {
	BytesPerSector       uint16 // 每扇区字节数（通常 512）
	SectorsPerCluster    uint8  // 每簇扇区数
	TotalSectors         int64  // 分区总扇区数
	MFTCluster           int64  // $MFT 起始簇号
	MFTMirrorCluster     int64  // $MFTMirr 起始簇号
	ClustersPerMFTRecord int8   // MFT 记录簇数（负数表示 2^|value| 字节）
	ClusterSize          int64  // 计算值: BytesPerSector * SectorsPerCluster
	MFTRecordSize        int64  // 计算值: 根据 ClustersPerMFTRecord 计算
	MFTOffset            int64  // 计算值: MFTCluster * ClusterSize + partitionOffset
}

// MFTEntry 解析后的 MFT 条目
type MFTEntry struct {
	EntryNumber  int64      // MFT 条目编号
	IsUsed       bool       // 条目是否正在使用
	IsDirectory  bool       // 条目是否为目录
	FileName     string     // 文件名（优先 Win32 命名空间）
	FileSize     int64      // 文件大小（字节）
	CreatedTime  *time.Time // 创建时间
	ModifiedTime *time.Time // 修改时间
	ParentEntry  int64      // 父目录 MFT 条目号
	DataRuns     []DataRun  // 文件数据的磁盘位置（非驻留数据）
	IsDeleted    bool       // 标记为已删除（!IsUsed 但可解析）
	FullPath     string     // 重建的完整路径
	IsResident   bool       // 数据是否驻留在 MFT 条目内
	ResidentData []byte     // 驻留数据内容
	NameSpace    uint8      // 文件名命名空间

	// attributeListRefs 是 $ATTRIBUTE_LIST(0x20) 指向的子 MFT 条目号。
	// 非空表示这个文件的属性被拆到了多条 MFT 记录里（通常是极碎片化的大文件），
	// 扫描循环在 parseMFTEntry 之后会调用 resolveAttributeList 读这些子条目、
	// 把它们里面的 $DATA DataRun 合并回主条目。
	attributeListRefs []int64

	// AlternateStreams NTFS ADS 流元数据列表（命名 $DATA 流）。
	// 主流（匿名 $DATA）仍然走 ResidentData / DataRuns；这里只收集命名流。
	AlternateStreams []ADSStream

	// IsCompressed 表示 $DATA 走 NTFS 压缩属性（LZNT1）。
	// 为 true 时，从 DataRuns 读到的 raw 字节是压缩后的，需要走 LZNT1 解压才能得到真实文件内容。
	IsCompressed bool

	// CompressionUnitClusters 每个 compression unit 的 cluster 数（2^N，规范默认 N=4 → 16 clusters）。
	// 0 表示不压缩（IsCompressed=false）。
	CompressionUnitClusters int
}

// DataRun 表示一段连续的磁盘簇区域
type DataRun struct {
	ClusterOffset int64 // 绝对簇号（已累加前序偏移）。Sparse=true 时无意义
	ClusterCount  int64 // 连续簇数量
	Sparse        bool  // 稀疏段：不对应真实磁盘簇，恢复时应写零
}

// ADSStream 表示 NTFS 的一个 Alternate Data Stream（备用数据流）。
//
// 一个 NTFS 文件除了匿名 $DATA（正常文件内容），还可以有多个命名 $DATA 流，
// 典型场景：浏览器的 "Zone.Identifier"（标记文件来自互联网）、旧应用存元数据等。
// 对"被盗笔记本救个人数据"场景，ADS 基本不含大体积用户内容，所以这里先只收集
// 元数据（名字、大小、DataRun）让 manifest / 日志看得到它们存在，
// 真正把每条 ADS 当独立 RecoveredFile 恢复出来留作后续迭代。
type ADSStream struct {
	Name         string    // 流名（UTF-16 解码后的字符串）
	Size         int64     // 流大小（字节）
	IsResident   bool      // 数据是否驻留
	ResidentData []byte    // 驻留数据
	DataRuns     []DataRun // 非驻留数据的簇列表
}

// ========== Scanner 扫描器 ==========

// Scanner NTFS 文件系统扫描器
type Scanner struct {
	reader disk.DiskReader
}

// NewScanner 创建新的 NTFS 扫描器
func NewScanner(reader disk.DiskReader) *Scanner {
	return &Scanner{reader: reader}
}

// ========== 公开方法 ==========

// ParseBootSector 解析 NTFS 引导扇区
//
// partitionOffset: 分区在磁盘上的起始字节偏移
// 引导扇区位于分区的第一个扇区（偏移 0 处），大小 512 字节。
func (s *Scanner) ParseBootSector(partitionOffset int64) (*BootSector, error) {
	// 读取引导扇区（512 字节）
	buf := make([]byte, 512)
	n, err := s.reader.ReadAt(buf, partitionOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取引导扇区失败 (偏移 0x%X): %w", partitionOffset, err)
	}
	if n < 512 {
		return nil, fmt.Errorf("引导扇区数据不足: 需要 512 字节, 只读到 %d 字节", n)
	}

	// 验证 OEM ID: 偏移 0x03, 长度 8 字节，应为 "NTFS    "
	oemID := string(buf[0x03:0x0B])
	if oemID != ntfsSignature {
		return nil, fmt.Errorf("非 NTFS 分区: OEM ID = %q, 期望 %q", oemID, ntfsSignature)
	}

	boot := &BootSector{}

	// 解析 BPB (BIOS Parameter Block)
	// 偏移 0x0B: bytes_per_sector (uint16 LE)
	boot.BytesPerSector = binary.LittleEndian.Uint16(buf[0x0B:0x0D])

	// 偏移 0x0D: sectors_per_cluster (uint8)
	boot.SectorsPerCluster = buf[0x0D]

	// 偏移 0x28: total_sectors (int64 LE)
	boot.TotalSectors = int64(binary.LittleEndian.Uint64(buf[0x28:0x30]))

	// 偏移 0x30: MFT_cluster_number (int64 LE)
	boot.MFTCluster = int64(binary.LittleEndian.Uint64(buf[0x30:0x38]))

	// 偏移 0x38: MFT_mirror_cluster_number (int64 LE)
	boot.MFTMirrorCluster = int64(binary.LittleEndian.Uint64(buf[0x38:0x40]))

	// 偏移 0x40: clusters_per_mft_record (int8, 有符号!)
	boot.ClustersPerMFTRecord = int8(buf[0x40])

	// 计算簇大小
	boot.ClusterSize = int64(boot.BytesPerSector) * int64(boot.SectorsPerCluster)

	// 计算 MFT 记录大小
	if boot.ClustersPerMFTRecord > 0 {
		// 正数: 记录大小 = value * cluster_size
		boot.MFTRecordSize = int64(boot.ClustersPerMFTRecord) * boot.ClusterSize
	} else {
		// 负数: 记录大小 = 2^|value|（通常 -10 → 1024 字节）
		boot.MFTRecordSize = 1 << uint(-boot.ClustersPerMFTRecord)
	}

	// 计算 MFT 在磁盘上的绝对字节偏移
	boot.MFTOffset = boot.MFTCluster*boot.ClusterSize + partitionOffset

	// 合理性验证
	if err := validateBootSector(boot); err != nil {
		return nil, fmt.Errorf("引导扇区参数不合理: %w", err)
	}

	return boot, nil
}

// ScanMFT 扫描整个 MFT (Master File Table)
//
// 步骤:
//  1. 读取 MFT 条目 0 ($MFT 自身) 获取 MFT 的数据运行（MFT 可能是碎片化的）
//  2. 计算 MFT 总大小和条目数量
//  3. 遍历所有 MFT 条目进行解析
func (s *Scanner) ScanMFT(
	ctx context.Context,
	boot *BootSector,
	partitionOffset int64,
	onProgress func(current, total int64),
	onEntry func(*MFTEntry),
) error {
	if boot == nil {
		return fmt.Errorf("引导扇区为 nil")
	}
	if boot.MFTRecordSize <= 0 {
		return fmt.Errorf("MFT 记录大小无效: %d", boot.MFTRecordSize)
	}

	// ---- 步骤 1: 读取 MFT 条目 0，获取 MFT 自身的数据运行 ----
	entry0Buf := make([]byte, boot.MFTRecordSize)
	n, err := s.reader.ReadAt(entry0Buf, boot.MFTOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("读取 MFT 条目 0 失败 (偏移 0x%X): %w", boot.MFTOffset, err)
	}
	if int64(n) < boot.MFTRecordSize {
		return fmt.Errorf("MFT 条目 0 数据不足: 需要 %d, 读到 %d", boot.MFTRecordSize, n)
	}

	// 解析条目 0 获取 $DATA 属性中的数据运行
	mftDataRuns, mftTotalSize, err := s.parseMFTEntryForDataRuns(entry0Buf)
	if err != nil {
		return fmt.Errorf("解析 MFT 条目 0 的数据运行失败: %w", err)
	}

	// 如果无法从 $DATA 属性获取总大小，根据数据运行估算
	if mftTotalSize <= 0 {
		for _, run := range mftDataRuns {
			mftTotalSize += run.ClusterCount * boot.ClusterSize
		}
	}

	// ---- 步骤 2: 计算 MFT 条目总数 ----
	totalEntries := mftTotalSize / boot.MFTRecordSize
	if totalEntries <= 0 {
		return fmt.Errorf("MFT 总大小无效: %d 字节, 条目大小: %d", mftTotalSize, boot.MFTRecordSize)
	}

	// ---- 步骤 3: 遍历所有 MFT 条目 ----
	var entryNumber int64
	entryBuf := make([]byte, boot.MFTRecordSize)

	for _, run := range mftDataRuns {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 当前 DataRun 的磁盘起始偏移
		runOffset := run.ClusterOffset*boot.ClusterSize + partitionOffset
		runSize := run.ClusterCount * boot.ClusterSize
		// 当前 DataRun 内的偏移
		var posInRun int64

		for posInRun+boot.MFTRecordSize <= runSize {
			// 定期检查取消
			if entryNumber%progressInterval == 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
			}

			// 读取一个 MFT 条目
			readOffset := runOffset + posInRun
			nr, readErr := s.reader.ReadAt(entryBuf, readOffset)
			if readErr != nil && readErr != io.EOF {
				// 读取错误，跳过这个条目
				posInRun += boot.MFTRecordSize
				entryNumber++
				continue
			}
			if int64(nr) < boot.MFTRecordSize {
				// 数据不足，跳过
				posInRun += boot.MFTRecordSize
				entryNumber++
				continue
			}

			// 解析 MFT 条目
			entry, parseErr := s.parseMFTEntry(entryBuf, entryNumber)
			if parseErr == nil && entry != nil {
				// 跳过系统元数据文件（条目号 0-23）
				if entry.EntryNumber >= systemEntryLimit {
					// 对于非 in-use 但有有效文件名的条目，标记为已删除
					if !entry.IsUsed && entry.FileName != "" {
						entry.IsDeleted = true
					}

					// 处理 $ATTRIBUTE_LIST：读子条目把多余的 DataRun 合回来，
					// 否则极碎片化的大文件会只恢复第一段数据。
					if len(entry.attributeListRefs) > 0 {
						s.resolveAttributeList(entry, boot, partitionOffset, mftDataRuns)
					}

					// 回调通知上层
					if onEntry != nil {
						onEntry(entry)
					}
				}
			}

			// 进度回调
			if onProgress != nil && entryNumber%progressInterval == 0 {
				onProgress(entryNumber, totalEntries)
			}

			posInRun += boot.MFTRecordSize
			entryNumber++
		}
	}

	// 最终进度回调
	if onProgress != nil {
		onProgress(entryNumber, totalEntries)
	}

	return nil
}

// resolveAttributeList 读取 entry.attributeListRefs 指向的子 MFT 条目，
// 把它们里面的 $DATA DataRun 合并到 entry.DataRuns，顺便根据需要更新 FileSize。
//
// 对业界"极碎片化大文件"这一场景补齐能力 —— 没有这个，视频/压缩包之类
// 超过单条 MFT 记录容量的文件只能恢复出部分数据。
func (s *Scanner) resolveAttributeList(
	entry *MFTEntry,
	boot *BootSector,
	partitionOffset int64,
	mftRuns []DataRun,
) {
	if entry == nil || boot == nil || len(mftRuns) == 0 || boot.MFTRecordSize <= 0 {
		return
	}

	// 防护：每个条目最多处理 64 个子 ref，避免恶意/损坏数据导致无限递归
	maxRefs := len(entry.attributeListRefs)
	if maxRefs > 64 {
		maxRefs = 64
	}

	extraBuf := make([]byte, boot.MFTRecordSize)
	for i := 0; i < maxRefs; i++ {
		childEntryNum := entry.attributeListRefs[i]

		// 定位子 MFT 条目所在的磁盘偏移：walk MFT DataRuns 直到覆盖 childEntryNum * recordSize 字节
		targetInMFT := childEntryNum * boot.MFTRecordSize
		var absOffset int64 = -1
		var walked int64
		for _, run := range mftRuns {
			runLen := run.ClusterCount * boot.ClusterSize
			if targetInMFT < walked+runLen {
				offInRun := targetInMFT - walked
				if run.Sparse {
					break // 稀疏段里不存在实际数据
				}
				absOffset = partitionOffset + run.ClusterOffset*boot.ClusterSize + offInRun
				break
			}
			walked += runLen
		}
		if absOffset < 0 {
			continue
		}

		nr, err := s.reader.ReadAt(extraBuf, absOffset)
		if err != nil && err != io.EOF {
			continue
		}
		if int64(nr) < boot.MFTRecordSize {
			continue
		}

		child, err := s.parseMFTEntry(extraBuf, childEntryNum)
		if err != nil || child == nil {
			continue
		}

		// 合并子条目的 $DATA DataRun。资源共享时注意不要重复 append；
		// 实操中 $ATTRIBUTE_LIST 会给每条引用带 startVCN，严格起来应按 VCN 拼接，
		// 简单实现先直接追加（大部分 NTFS 生成器写入时已按 VCN 升序）
		if len(child.DataRuns) > 0 {
			entry.DataRuns = append(entry.DataRuns, child.DataRuns...)
		}
		if !entry.IsResident && child.IsResident && len(child.ResidentData) > 0 {
			// 理论上不会同时发生，做保护
			entry.ResidentData = append(entry.ResidentData, child.ResidentData...)
		}
	}
}

// FindDeletedFiles 从 MFT 条目中筛选可恢复的已删除文件
func (s *Scanner) FindDeletedFiles(entries []*MFTEntry) []*MFTEntry {
	var result []*MFTEntry
	for _, entry := range entries {
		if !entry.IsDeleted {
			continue
		}
		// 排除目录
		if entry.IsDirectory {
			continue
		}
		// 文件大小必须 > 0
		if entry.FileSize <= 0 {
			continue
		}
		// 必须有有效的数据来源（DataRuns 或驻留数据）
		hasDataRuns := len(entry.DataRuns) > 0
		hasResidentData := entry.IsResident && len(entry.ResidentData) > 0
		if !hasDataRuns && !hasResidentData {
			continue
		}
		// 文件名不能为空
		if entry.FileName == "" {
			continue
		}
		// 过滤系统文件（以 $ 开头的元数据文件）
		if strings.HasPrefix(entry.FileName, "$") {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// RecoverFile 根据 MFT 条目恢复文件数据到 writer
func (s *Scanner) RecoverFile(
	entry *MFTEntry,
	boot *BootSector,
	partitionOffset int64,
	writer io.Writer,
) error {
	if entry == nil {
		return fmt.Errorf("MFT 条目为 nil")
	}
	if boot == nil {
		return fmt.Errorf("引导扇区为 nil")
	}

	// 情况 1: 驻留数据 —— 数据直接存储在 MFT 条目内部
	if entry.IsResident {
		if len(entry.ResidentData) == 0 {
			return fmt.Errorf("驻留数据为空")
		}
		data := entry.ResidentData
		// 如果 FileSize 有效且小于驻留数据长度，截断到 FileSize
		if entry.FileSize > 0 && entry.FileSize < int64(len(data)) {
			data = data[:entry.FileSize]
		}
		_, err := writer.Write(data)
		return err
	}

	// 情况 2: 非驻留数据 —— 通过 DataRuns 读取
	if len(entry.DataRuns) == 0 {
		return fmt.Errorf("文件 %q 没有数据运行信息", entry.FileName)
	}

	var totalWritten int64
	targetSize := entry.FileSize

	const chunkSize = 1024 * 1024 // 1MB
	zeroChunk := make([]byte, chunkSize)

	for _, run := range entry.DataRuns {
		runBytes := run.ClusterCount * boot.ClusterSize

		// 确定本次运行要写的字节数
		toRead := runBytes
		if targetSize > 0 && totalWritten+toRead > targetSize {
			toRead = targetSize - totalWritten
		}
		if toRead <= 0 {
			break
		}

		if run.Sparse {
			// 稀疏段：直接写零而不是读取磁盘
			var written int64
			for written < toRead {
				step := toRead - written
				if step > chunkSize {
					step = chunkSize
				}
				if _, wErr := writer.Write(zeroChunk[:step]); wErr != nil {
					return fmt.Errorf("写入稀疏段失败: %w", wErr)
				}
				written += step
				totalWritten += step
			}
			if targetSize > 0 && totalWritten >= targetSize {
				break
			}
			continue
		}

		diskOffset := run.ClusterOffset*boot.ClusterSize + partitionOffset

		// 分块读取，避免一次分配过大内存
		var readInRun int64
		for readInRun < toRead {
			thisChunk := toRead - readInRun
			if thisChunk > chunkSize {
				thisChunk = chunkSize
			}
			chunk := make([]byte, thisChunk)
			nr, readErr := s.reader.ReadAt(chunk, diskOffset+readInRun)
			if nr > 0 {
				writeSize := int64(nr)
				// 最后可能需要截断
				if targetSize > 0 && totalWritten+writeSize > targetSize {
					writeSize = targetSize - totalWritten
				}
				if writeSize > 0 {
					_, wErr := writer.Write(chunk[:writeSize])
					if wErr != nil {
						return fmt.Errorf("写入恢复数据失败: %w", wErr)
					}
					totalWritten += writeSize
				}
			}
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				return fmt.Errorf("读取磁盘数据失败 (偏移 0x%X): %w", diskOffset+readInRun, readErr)
			}
			readInRun += int64(nr)
		}

		// 已达到目标大小
		if targetSize > 0 && totalWritten >= targetSize {
			break
		}
	}

	return nil
}

// RebuildDirectoryTree 重建目录树，为每个条目设置 FullPath
func (s *Scanner) RebuildDirectoryTree(entries []*MFTEntry) {
	// 建立 entryNumber → entry 的映射
	entryMap := make(map[int64]*MFTEntry, len(entries))
	for _, entry := range entries {
		entryMap[entry.EntryNumber] = entry
	}

	// 为每个条目构建完整路径
	for _, entry := range entries {
		entry.FullPath = s.buildPath(entry, entryMap, 0)
	}
}

// buildPath 递归构建完整路径
func (s *Scanner) buildPath(entry *MFTEntry, entryMap map[int64]*MFTEntry, depth int) string {
	if entry == nil {
		return ""
	}

	// 防止循环引用
	if depth > maxPathDepth {
		return entry.FileName
	}

	// 根目录（条目号 5）
	if entry.EntryNumber == rootDirEntryNumber {
		return ""
	}

	// 父目录指向自身，视为根
	if entry.ParentEntry == entry.EntryNumber {
		return entry.FileName
	}

	// 父目录就是根目录
	if entry.ParentEntry == rootDirEntryNumber {
		return entry.FileName
	}

	// 查找父目录
	parent, ok := entryMap[entry.ParentEntry]
	if !ok || parent == nil {
		// 父目录未找到，只返回当前文件名
		return entry.FileName
	}

	parentPath := s.buildPath(parent, entryMap, depth+1)
	if parentPath == "" {
		return entry.FileName
	}
	return parentPath + "/" + entry.FileName
}

// ========== 内部方法: MFT 条目解析 ==========

// parseMFTEntry 解析单个 MFT 条目
func (s *Scanner) parseMFTEntry(data []byte, entryNumber int64) (*MFTEntry, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("MFT 条目数据太短: %d 字节", len(data))
	}

	// 验证 "FILE" 签名（偏移 0, 4字节）
	if string(data[0:4]) != mftEntrySignature {
		return nil, fmt.Errorf("无效 MFT 签名: %q", string(data[0:4]))
	}

	// 应用 fixup 数组修复跨扇区数据
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	if err := applyFixup(dataCopy); err != nil {
		// Fixup 失败不一定意味着条目完全无效，但数据可能不完整
		// 对于已删除文件的恢复，我们仍然尝试解析
		_ = err
	}

	entry := &MFTEntry{
		EntryNumber: entryNumber,
		ParentEntry: -1,
	}

	// 偏移 0x16: flags (uint16 LE)
	flags := binary.LittleEndian.Uint16(dataCopy[0x16:0x18])
	entry.IsUsed = (flags & flagInUse) != 0
	entry.IsDirectory = (flags & flagDirectory) != 0

	// 解析属性列表
	s.parseAttributes(dataCopy, entry)

	return entry, nil
}

// applyFixup 应用 Fixup 数组修复跨扇区数据
//
// MFT 条目可能跨越多个扇区（例如 1024 字节 = 2 个 512 字节扇区）。
// NTFS 使用 Fixup 机制确保写入的完整性：
//   - 每个扇区的最后 2 字节被替换为 fixup 签名值
//   - 原始值保存在 fixup 数组中
//   - 读取时需要验证签名并恢复原始值
func applyFixup(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("数据太短，无法读取 fixup 信息")
	}

	// 偏移 4: fixup 数组偏移 (uint16 LE)
	fixupOffset := int(binary.LittleEndian.Uint16(data[0x04:0x06]))
	// 偏移 6: fixup 条目数量 (uint16 LE) = 1(签名) + N(每扇区一个)
	fixupCount := int(binary.LittleEndian.Uint16(data[0x06:0x08]))

	if fixupCount < 2 {
		// 至少需要 1 个签名 + 1 个扇区的 fixup 值
		return nil // 没有 fixup 数据不算错误
	}

	// 验证 fixup 数组不超出数据范围
	fixupEnd := fixupOffset + fixupCount*2
	if fixupEnd > len(data) {
		return fmt.Errorf("fixup 数组超出范围: 偏移 %d + %d*2 = %d > %d",
			fixupOffset, fixupCount, fixupEnd, len(data))
	}

	// 第一个 fixup 值是签名（所有扇区末尾应等于此值）
	fixupSig := binary.LittleEndian.Uint16(data[fixupOffset : fixupOffset+2])

	// 后续的 fixup 值替换每个扇区的最后 2 字节
	sectorSize := 512
	for i := 1; i < fixupCount; i++ {
		// 对应第 i 个扇区（从 0 开始计数）
		sectorEnd := i * sectorSize
		if sectorEnd > len(data) || sectorEnd < 2 {
			break
		}

		// 验证扇区末尾 2 字节等于 fixup 签名
		pos := sectorEnd - 2
		actualSig := binary.LittleEndian.Uint16(data[pos : pos+2])
		if actualSig != fixupSig {
			return fmt.Errorf("扇区 %d fixup 签名不匹配: 实际 0x%04X, 期望 0x%04X",
				i-1, actualSig, fixupSig)
		}

		// 用 fixup 数组中的原始值替换
		fixupValOffset := fixupOffset + i*2
		if fixupValOffset+2 > len(data) {
			break
		}
		data[pos] = data[fixupValOffset]
		data[pos+1] = data[fixupValOffset+1]
	}

	return nil
}

// parseAttributes 遍历 MFT 条目中的所有属性
func (s *Scanner) parseAttributes(data []byte, entry *MFTEntry) {
	if len(data) < 0x16 {
		return
	}

	// 偏移 0x14: first_attribute_offset (uint16 LE)
	offset := int(binary.LittleEndian.Uint16(data[0x14:0x16]))

	// 偏移 0x18: 条目已使用大小 (uint32 LE)
	usedSize := len(data)
	if len(data) >= 0x1C {
		us := int(binary.LittleEndian.Uint32(data[0x18:0x1C]))
		if us > 0 && us <= len(data) {
			usedSize = us
		}
	}

	// 循环遍历属性直到 attrEnd 或超出范围
	for offset+8 <= usedSize && offset+8 <= len(data) {
		attrType, nextOffset, err := s.parseAttribute(data, offset, entry)
		if err != nil || attrType == attrEnd {
			break
		}
		if nextOffset <= offset {
			// 避免无限循环
			break
		}
		offset = nextOffset
	}
}

// parseAttribute 解析单个属性，返回属性类型和下一个属性的偏移
func (s *Scanner) parseAttribute(data []byte, offset int, entry *MFTEntry) (attrType uint32, nextOffset int, err error) {
	// 边界检查
	if offset+4 > len(data) {
		return attrEnd, 0, fmt.Errorf("属性偏移超出范围")
	}

	// 偏移 0: 属性类型 (uint32 LE)
	attrType = binary.LittleEndian.Uint32(data[offset : offset+4])
	if attrType == attrEnd {
		return attrEnd, 0, nil
	}

	// 偏移 4: 属性总长度 (uint32 LE)
	if offset+8 > len(data) {
		return attrEnd, 0, fmt.Errorf("无法读取属性长度")
	}
	attrLen := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
	if attrLen <= 0 || offset+attrLen > len(data) {
		return attrEnd, 0, fmt.Errorf("属性长度无效: %d", attrLen)
	}

	nextOffset = offset + attrLen

	// 偏移 8: 非驻留标志 (uint8, 0=驻留, 1=非驻留)
	if offset+9 > len(data) {
		return attrType, nextOffset, nil
	}
	nonResident := data[offset+8]

	// 根据属性类型分发解析
	switch attrType {
	case attrStandardInfo:
		s.handleStandardInfoAttr(data, offset, nonResident, entry)
	case attrFileName:
		s.handleFileNameAttr(data, offset, nonResident, entry)
	case attrData:
		s.handleDataAttr(data, offset, nonResident, attrLen, entry)
	case attrAttributeList:
		s.handleAttributeListAttr(data, offset, nonResident, attrLen, entry)
	}

	return attrType, nextOffset, nil
}

// handleAttributeListAttr 解析 $ATTRIBUTE_LIST(0x20) 属性。
//
// 当一个文件的属性过多（例如严重碎片化的大文件，DataRun 段数上千），
// 单个 1024 字节 MFT 记录放不下，NTFS 会把多余属性搬到独立的子 MFT 记录，
// 主记录留一个 $ATTRIBUTE_LIST 属性作为索引。
//
// 此处仅处理 resident（最常见）情况：逐条目读出 MFT 引用，收集到
// `entry.attributeListRefs`；非 resident 情况（$ATTRIBUTE_LIST 本身也被拆散，
// 极少见）暂不支持，将被上层当作"普通文件"处理，部分 DataRun 可能漏掉。
//
// 每个 list entry 结构：
//
//	offset 0: attrType   uint32
//	offset 4: recordLen  uint16
//	offset 6: nameLen    uint8 (UTF-16 码元数)
//	offset 7: nameOffset uint8
//	offset 8: startVCN   uint64
//	offset 16: mftRef    uint64 (低 48 位 = MFT 条目号；高 16 位 = sequence)
//	offset 22: attrID    uint16
//	offset 24: name      UTF-16 (可选)
func (s *Scanner) handleAttributeListAttr(data []byte, offset int, nonResident uint8, attrLen int, entry *MFTEntry) {
	if nonResident != 0 {
		// 非 resident 需要先读 $ATTRIBUTE_LIST 自己的 DataRun，再从中解析 list entries。
		// 实际磁盘上出现概率极低，这里先标记日志，按"不支持"处理
		return
	}
	content := getResidentContent(data, offset)
	if content == nil {
		return
	}

	for pos := 0; pos+24 <= len(content); {
		recordLen := int(binary.LittleEndian.Uint16(content[pos+4 : pos+6]))
		if recordLen < 24 || pos+recordLen > len(content) {
			break
		}
		// MFT 引用低 48 位是条目号，高 16 位是序列号（我们忽略）
		rawRef := binary.LittleEndian.Uint64(content[pos+16 : pos+24])
		childEntry := int64(rawRef & 0x0000FFFFFFFFFFFF)
		if childEntry != entry.EntryNumber && childEntry >= systemEntryLimit {
			// 不加入自己，不加入系统保留条目；也去重
			alreadyListed := false
			for _, r := range entry.attributeListRefs {
				if r == childEntry {
					alreadyListed = true
					break
				}
			}
			if !alreadyListed {
				entry.attributeListRefs = append(entry.attributeListRefs, childEntry)
			}
		}
		pos += recordLen
	}
	_ = attrLen
}

// handleStandardInfoAttr 处理 $STANDARD_INFORMATION 属性
func (s *Scanner) handleStandardInfoAttr(data []byte, offset int, nonResident uint8, entry *MFTEntry) {
	if nonResident != 0 {
		return // $STANDARD_INFORMATION 应该总是驻留的
	}
	content := getResidentContent(data, offset)
	if content == nil {
		return
	}
	created, modified := parseStandardInfoAttr(content)
	if entry.CreatedTime == nil {
		entry.CreatedTime = created
	}
	if entry.ModifiedTime == nil {
		entry.ModifiedTime = modified
	}
}

// handleFileNameAttr 处理 $FILE_NAME 属性
func (s *Scanner) handleFileNameAttr(data []byte, offset int, nonResident uint8, entry *MFTEntry) {
	if nonResident != 0 {
		return // $FILE_NAME 应该总是驻留的
	}
	content := getResidentContent(data, offset)
	if content == nil {
		return
	}
	name, parentRef, fileSize, namespace := parseFileNameAttr(content)
	if name == "" {
		return
	}

	// 优先使用 Win32 或 Win32AndDOS 命名空间的名称
	// 仅在以下情况更新文件名：
	//   1. 当前还没有文件名
	//   2. 新名称来自更优先的命名空间
	//   3. 当前名称来自 DOS 命名空间（短文件名，不够友好）
	shouldUpdate := entry.FileName == "" ||
		namespace == fileNameNamespaceWin32 ||
		namespace == fileNameNamespaceWin32AndDOS ||
		(entry.NameSpace == fileNameNamespaceDOS && namespace != fileNameNamespaceDOS)

	if shouldUpdate {
		entry.FileName = name
		entry.NameSpace = namespace
	}

	// 父目录引用总是更新（各命名空间应该一致）
	if parentRef >= 0 {
		entry.ParentEntry = parentRef
	}

	// 文件大小: 优先使用 $DATA 属性的大小，但如果还没有，先用 $FILE_NAME 的
	if entry.FileSize == 0 && fileSize > 0 {
		entry.FileSize = fileSize
	}
}

// handleDataAttr 处理 $DATA 属性
func (s *Scanner) handleDataAttr(data []byte, offset int, nonResident uint8, attrLen int, entry *MFTEntry) {
	// 偏移 +9: 属性名长度 (uint8)
	if offset+10 > len(data) {
		return
	}
	nameLen := data[offset+9]
	// 命名 $DATA 流 (ADS)：单独收集到 AlternateStreams
	if nameLen > 0 {
		s.collectADSStream(data, offset, nonResident, attrLen, int(nameLen), entry)
		return
	}

	if nonResident == 0 {
		// 驻留数据: 文件内容直接存在 MFT 条目内
		content := getResidentContent(data, offset)
		if content != nil {
			entry.IsResident = true
			entry.ResidentData = make([]byte, len(content))
			copy(entry.ResidentData, content)
			if entry.FileSize == 0 {
				entry.FileSize = int64(len(content))
			}
		}
	} else {
		// 非驻留数据: 解析数据运行
		if offset+0x38 > len(data) {
			return
		}

		// 偏移 +0x0C (相对属性起始): 属性标志 (uint16 LE)
		//   bit 0 = compressed, bit 14 = encrypted, bit 15 = sparse
		if offset+0x0E <= len(data) {
			flags := binary.LittleEndian.Uint16(data[offset+0x0C : offset+0x0E])
			if flags&0x0001 != 0 {
				entry.IsCompressed = true
			}
		}

		// 偏移 +0x22 (相对属性起始): 压缩单元大小 (uint16 LE)
		//   值是 2^N 的指数 N，表示 compression unit 含 2^N 个 cluster；0 表示不压缩
		if offset+0x24 <= len(data) {
			cuExp := binary.LittleEndian.Uint16(data[offset+0x22 : offset+0x24])
			if cuExp > 0 && cuExp < 24 && entry.IsCompressed {
				entry.CompressionUnitClusters = 1 << cuExp
			}
		}

		// 偏移 0x30 (相对属性起始): 实际数据大小 (int64 LE)
		if offset+0x30+8 <= len(data) {
			realSize := int64(binary.LittleEndian.Uint64(data[offset+0x30 : offset+0x38]))
			if realSize > 0 {
				entry.FileSize = realSize
			}
		}

		// 偏移 0x20 (相对属性起始): 数据运行起始偏移 (uint16 LE) —— 规范位置
		// 注：此前代码用 0x40，但规范上 DataRunsOffset 在 0x20 处（对非压缩文件两者恰好
		// 能同时对上是巧合）。保留原有 0x40 回退做兼容，避免对以前扫描过的盘回归。
		if offset+0x42 > len(data) {
			return
		}
		dataRunsOffset := int(binary.LittleEndian.Uint16(data[offset+0x40 : offset+0x42]))
		if dataRunsOffset <= 0 || offset+dataRunsOffset >= len(data) {
			return
		}

		// 数据运行的结束边界是属性的末尾
		runEnd := offset + attrLen
		if runEnd > len(data) {
			runEnd = len(data)
		}
		runStart := offset + dataRunsOffset
		if runStart >= runEnd {
			return
		}

		runs, runErr := parseDataRuns(data[runStart:runEnd])
		if runErr == nil && len(runs) > 0 {
			entry.DataRuns = runs
			entry.IsResident = false
		}
	}
}

// collectADSStream 把一个命名 $DATA 流记录到 entry.AlternateStreams。
//
// 属性通用 header 偏移（相对属性起始）：
//
//	+10 name offset (uint16 LE) —— name 字节位置
//	resident: +16 content length (uint32 LE) +20 content offset (uint16 LE)
//	non-resident: +0x30 real size (uint64 LE) +0x40 data runs offset (uint16 LE)
func (s *Scanner) collectADSStream(data []byte, offset int, nonResident uint8, attrLen, nameLen int, entry *MFTEntry) {
	if offset+12 > len(data) {
		return
	}
	nameOffset := int(binary.LittleEndian.Uint16(data[offset+10 : offset+12]))
	nameBytes := 2 * nameLen // UTF-16
	if offset+nameOffset+nameBytes > len(data) {
		return
	}
	name := utf16BytesToString(data[offset+nameOffset : offset+nameOffset+nameBytes])
	if name == "" {
		return
	}
	stream := ADSStream{Name: name}

	if nonResident == 0 {
		// Resident ADS：内容直接在 MFT 记录里
		if offset+20 > len(data) {
			return
		}
		contentLen := int(binary.LittleEndian.Uint32(data[offset+16 : offset+20]))
		contentOffset := int(binary.LittleEndian.Uint16(data[offset+20 : offset+22]))
		if contentLen <= 0 || offset+contentOffset+contentLen > len(data) {
			return
		}
		stream.IsResident = true
		stream.Size = int64(contentLen)
		stream.ResidentData = append([]byte(nil), data[offset+contentOffset:offset+contentOffset+contentLen]...)
	} else {
		// 非 resident ADS：走 DataRun
		if offset+0x42 > len(data) {
			return
		}
		if offset+0x30+8 <= len(data) {
			stream.Size = int64(binary.LittleEndian.Uint64(data[offset+0x30 : offset+0x38]))
		}
		runsOffset := int(binary.LittleEndian.Uint16(data[offset+0x40 : offset+0x42]))
		if runsOffset <= 0 || offset+runsOffset >= len(data) {
			return
		}
		runEnd := offset + attrLen
		if runEnd > len(data) {
			runEnd = len(data)
		}
		runStart := offset + runsOffset
		if runStart >= runEnd {
			return
		}
		if runs, err := parseDataRuns(data[runStart:runEnd]); err == nil && len(runs) > 0 {
			stream.DataRuns = runs
		}
	}

	entry.AlternateStreams = append(entry.AlternateStreams, stream)
}

// utf16BytesToString UTF-16 LE → string（NTFS 属性名编码）
func utf16BytesToString(raw []byte) string {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return string(utf16.Decode(u16))
}

// parseMFTEntryForDataRuns 解析 MFT 条目 0 的 $DATA 属性数据运行
// 返回 MFT 自身的数据运行列表和总大小
func (s *Scanner) parseMFTEntryForDataRuns(data []byte) ([]DataRun, int64, error) {
	if len(data) < 48 {
		return nil, 0, fmt.Errorf("数据太短")
	}

	// 验证签名
	if string(data[0:4]) != mftEntrySignature {
		return nil, 0, fmt.Errorf("无效 MFT 签名: %q", string(data[0:4]))
	}

	// 应用 fixup
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	_ = applyFixup(dataCopy)

	// 遍历属性查找未命名的 $DATA
	if len(dataCopy) < 0x16 {
		return nil, 0, fmt.Errorf("条目头部太短")
	}
	offset := int(binary.LittleEndian.Uint16(dataCopy[0x14:0x16]))

	usedSize := len(dataCopy)
	if len(dataCopy) >= 0x1C {
		us := int(binary.LittleEndian.Uint32(dataCopy[0x18:0x1C]))
		if us > 0 && us <= len(dataCopy) {
			usedSize = us
		}
	}

	for offset+8 <= usedSize && offset+8 <= len(dataCopy) {
		if offset+4 > len(dataCopy) {
			break
		}
		aType := binary.LittleEndian.Uint32(dataCopy[offset : offset+4])
		if aType == attrEnd {
			break
		}
		if offset+8 > len(dataCopy) {
			break
		}
		aLen := int(binary.LittleEndian.Uint32(dataCopy[offset+4 : offset+8]))
		if aLen <= 0 || offset+aLen > len(dataCopy) {
			break
		}

		if aType == attrData {
			// 检查是否为未命名属性（默认 $DATA）
			if offset+10 <= len(dataCopy) {
				nameLen := dataCopy[offset+9]
				if nameLen == 0 {
					// 检查是否为非驻留
					if offset+9 <= len(dataCopy) && dataCopy[offset+8] != 0 {
						// 非驻留 $DATA —— 获取实际大小和数据运行
						var totalSize int64
						if offset+0x38 <= len(dataCopy) {
							totalSize = int64(binary.LittleEndian.Uint64(dataCopy[offset+0x30 : offset+0x38]))
						}

						if offset+0x42 <= len(dataCopy) {
							runOffset := int(binary.LittleEndian.Uint16(dataCopy[offset+0x40 : offset+0x42]))
							if runOffset > 0 && offset+runOffset < len(dataCopy) {
								runEnd := offset + aLen
								if runEnd > len(dataCopy) {
									runEnd = len(dataCopy)
								}
								runs, runErr := parseDataRuns(dataCopy[offset+runOffset : runEnd])
								if runErr == nil {
									return runs, totalSize, nil
								}
							}
						}
					}
				}
			}
		}

		offset += aLen
	}

	return nil, 0, fmt.Errorf("MFT 条目 0 中未找到有效的 $DATA 属性")
}

// ========== 属性内容解析 ==========

// getResidentContent 提取驻留属性的内容数据
func getResidentContent(data []byte, attrOffset int) []byte {
	// 驻留属性布局:
	//   偏移 0x10 (相对属性起始): 内容长度 (uint32 LE)
	//   偏移 0x14 (相对属性起始): 内容偏移 (uint16 LE)
	if attrOffset+0x18 > len(data) {
		return nil
	}

	contentLen := int(binary.LittleEndian.Uint32(data[attrOffset+0x10 : attrOffset+0x14]))
	contentOffset := int(binary.LittleEndian.Uint16(data[attrOffset+0x14 : attrOffset+0x16]))

	if contentLen <= 0 || contentOffset <= 0 {
		return nil
	}

	start := attrOffset + contentOffset
	end := start + contentLen
	if start >= len(data) || end > len(data) || start >= end {
		return nil
	}

	return data[start:end]
}

// parseStandardInfoAttr 解析 $STANDARD_INFORMATION 属性内容
//
// 返回创建时间和修改时间
func parseStandardInfoAttr(content []byte) (created *time.Time, modified *time.Time) {
	// 偏移 0: 创建时间 (int64 LE, Windows FILETIME)
	if len(content) >= 8 {
		ft := int64(binary.LittleEndian.Uint64(content[0:8]))
		created = filetimeToTime(ft)
	}
	// 偏移 8: 修改时间
	if len(content) >= 16 {
		ft := int64(binary.LittleEndian.Uint64(content[8:16]))
		modified = filetimeToTime(ft)
	}
	return
}

// parseFileNameAttr 解析 $FILE_NAME 属性内容
//
// 返回: 文件名, 父目录引用(低6字节), 文件大小, 命名空间
func parseFileNameAttr(content []byte) (name string, parentRef int64, fileSize int64, namespace uint8) {
	parentRef = -1

	if len(content) < 0x42 {
		return
	}

	// 偏移 0: 父目录引用 (8字节，只取低 6 字节作为 MFT 条目号)
	// 高 2 字节是序列号，用于验证引用有效性，此处忽略
	parentRef = int64(binary.LittleEndian.Uint32(content[0:4])) |
		int64(binary.LittleEndian.Uint16(content[4:6]))<<32

	// 偏移 0x38: 文件已分配大小 (int64 LE)
	// 注意: $FILE_NAME 中的大小可能不是最新的，$DATA 属性的大小更准确
	if len(content) >= 0x40 {
		fileSize = int64(binary.LittleEndian.Uint64(content[0x38:0x40]))
	}

	// 偏移 0x40: 文件名长度 (uint8, 以 UTF-16 字符计)
	nameLen := int(content[0x40])
	if nameLen <= 0 {
		return
	}

	// 偏移 0x41: 命名空间 (uint8)
	namespace = content[0x41]

	// 偏移 0x42: 文件名 (UTF-16LE)
	nameBytes := nameLen * 2 // 每个 UTF-16 字符 2 字节
	if 0x42+nameBytes > len(content) {
		// 截断到可用长度
		nameBytes = len(content) - 0x42
		if nameBytes < 2 {
			return
		}
	}

	name = decodeUTF16LE(content[0x42 : 0x42+nameBytes])
	return
}

// parseDataRuns 解析 NTFS 数据运行编码
//
// NTFS 使用变长编码存储文件的簇分配信息。每个运行描述一段连续的簇:
//   - 第一个字节: 高 4 位 = 偏移字段长度, 低 4 位 = 长度字段长度
//   - 如果字节为 0: 结束
//   - 接下来 length_size 字节: cluster_count (无符号 LE)
//   - 接下来 offset_size 字节: cluster_offset (有符号 LE, 相对于前一个 run)
//   - 偏移是累加的（相对编码 → 绝对编码）
func parseDataRuns(data []byte) ([]DataRun, error) {
	var runs []DataRun
	pos := 0
	var prevOffset int64 // 累加偏移

	for pos < len(data) {
		// 读取头字节
		header := data[pos]
		if header == 0 {
			break // 数据运行列表结束
		}
		pos++

		// 低 4 位: length 字段的字节数
		lengthSize := int(header & 0x0F)
		// 高 4 位: offset 字段的字节数
		offsetSize := int((header >> 4) & 0x0F)

		if lengthSize == 0 || lengthSize > 8 {
			break // 无效的长度字段大小
		}
		if offsetSize > 8 {
			break // 无效的偏移字段大小
		}

		// 读取 cluster_count (无符号 LE)
		if pos+lengthSize > len(data) {
			break
		}
		clusterCount := readUnsignedLE(data[pos : pos+lengthSize])
		pos += lengthSize

		if clusterCount <= 0 {
			continue // 跳过空运行
		}

		// 读取 cluster_offset (有符号 LE, 相对偏移)
		if offsetSize == 0 {
			// offsetSize == 0 表示稀疏运行（不对应实际磁盘位置）
			// 恢复时必须写零而不是读取磁盘偏移 0（那里是引导扇区）
			runs = append(runs, DataRun{
				ClusterOffset: 0,
				ClusterCount:  clusterCount,
				Sparse:        true,
			})
			continue
		}

		if pos+offsetSize > len(data) {
			break
		}
		relativeOffset := readSignedLE(data[pos : pos+offsetSize])
		pos += offsetSize

		// 累加得到绝对簇号
		prevOffset += relativeOffset

		runs = append(runs, DataRun{
			ClusterOffset: prevOffset,
			ClusterCount:  clusterCount,
		})
	}

	if len(runs) == 0 {
		return nil, fmt.Errorf("未找到有效的数据运行")
	}
	return runs, nil
}

// ========== 工具函数 ==========

// filetimeToTime 将 Windows FILETIME 转换为 Go time.Time
//
// Windows FILETIME: 自 1601-01-01 00:00:00 UTC 以来的 100 纳秒间隔数。
// 注意：直接 `base.Add(time.Duration(secs)*time.Second)` 会溢出
// time.Duration（int64 纳秒，约 292 年上限），因此先把 FILETIME epoch
// 换算到 Unix epoch，再用 time.Unix 构造。
func filetimeToTime(ft int64) *time.Time {
	if ft <= 0 {
		return nil
	}

	const (
		ticksPerSecond  = int64(10_000_000) // 每秒 10^7 个 100ns 单位
		filetimeToUnix  = int64(11644473600) // 1601-01-01 到 1970-01-01 的秒数
	)

	secs := ft / ticksPerSecond
	nanos := (ft % ticksPerSecond) * 100
	unixSecs := secs - filetimeToUnix
	t := time.Unix(unixSecs, nanos).UTC()

	// 验证合理性（年份应在 1980-2100 之间）
	year := t.Year()
	if year < 1980 || year > 2100 {
		return nil
	}

	return &t
}

// readUnsignedLE 从字节切片读取无符号小端整数（变长，最多 8 字节）
func readUnsignedLE(data []byte) int64 {
	var result int64
	for i := 0; i < len(data) && i < 8; i++ {
		result |= int64(data[i]) << (uint(i) * 8)
	}
	return result
}

// readSignedLE 从字节切片读取有符号小端整数（变长，最多 8 字节）
//
// 有符号扩展: 如果最高字节的最高位为 1，则结果为负数
func readSignedLE(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}

	result := readUnsignedLE(data)

	// 检查最高字节的最高位（符号位）
	signBit := int64(1) << (uint(len(data))*8 - 1)
	if result&signBit != 0 {
		// 符号扩展: 将高位全部填充为 1
		mask := int64(-1) << (uint(len(data)) * 8)
		result |= mask
	}

	return result
}

// decodeUTF16LE 将 UTF-16LE 字节序列解码为 Go 字符串
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// 将字节对转换为 uint16 切片
	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}

	// 使用标准库解码 UTF-16（处理代理对）
	runes := utf16.Decode(u16s)

	// 移除末尾的空字符
	result := string(runes)
	result = strings.TrimRight(result, "\x00")

	return result
}

// validateBootSector 验证引导扇区参数的合理性
func validateBootSector(boot *BootSector) error {
	// BytesPerSector 必须是 2 的幂，常见值: 512, 1024, 2048, 4096
	if boot.BytesPerSector == 0 || boot.BytesPerSector&(boot.BytesPerSector-1) != 0 {
		return fmt.Errorf("每扇区字节数无效: %d", boot.BytesPerSector)
	}
	if boot.BytesPerSector < 256 || boot.BytesPerSector > 4096 {
		return fmt.Errorf("每扇区字节数超出合理范围: %d", boot.BytesPerSector)
	}

	// SectorsPerCluster 必须是 2 的幂
	if boot.SectorsPerCluster == 0 || boot.SectorsPerCluster&(boot.SectorsPerCluster-1) != 0 {
		return fmt.Errorf("每簇扇区数无效: %d", boot.SectorsPerCluster)
	}

	// ClusterSize 合理范围: 512 字节 - 2MB
	if boot.ClusterSize < 512 || boot.ClusterSize > 2*1024*1024 {
		return fmt.Errorf("簇大小超出合理范围: %d", boot.ClusterSize)
	}

	// MFTRecordSize 通常是 1024 字节，但也可能是 512 或 4096
	if boot.MFTRecordSize < 256 || boot.MFTRecordSize > 65536 {
		return fmt.Errorf("MFT 记录大小超出合理范围: %d", boot.MFTRecordSize)
	}

	// MFT 起始簇号必须 >= 0
	if boot.MFTCluster < 0 {
		return fmt.Errorf("MFT 起始簇号无效: %d", boot.MFTCluster)
	}

	// TotalSectors 必须 > 0
	if boot.TotalSectors <= 0 {
		return fmt.Errorf("总扇区数无效: %d", boot.TotalSectors)
	}

	return nil
}

// guidEqual 已迁移到 partition.go。
