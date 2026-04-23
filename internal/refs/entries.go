package refs

// ReFS Minstore B+ tree entry 解析 —— 在已索引的 MSB+ page 里尝试抽文件名和 stream 信息。
//
// **边界声明（非常重要）**：
//
// Microsoft **没有公开 ReFS 规范**。本实现基于：
//   - 社区逆向（reqrypt.org / dubeyko / reverse-engineering FS forensics）
//   - ReFS v3.x（Win 10 1709+）典型布局
//   - 对 Minstore page 结构的常见观察
//
// 因此本 entry 解析是 **best-effort**：
//   ✅ 识别 entry boundary（每个 entry 有固定 header）
//   ✅ 抽取 entry 内的 UTF-16 文件名候选
//   ✅ 启发式过滤：长度 [1, 255] 字符 + 合理字符集
//   ❌ 精确的 stream / extent list / allocation tree 解析
//   ❌ 目录层级还原（parent-child 关系在隔离的 ROOT B+tree 里）
//   ❌ copy-on-write 历史（ReFS 支持但需要 scavenger metadata）
//
// 用途：给用户展示"这个 ReFS 卷上看起来有这些文件名"；配合 carver 签名扫描仍可恢复
// 文件内容（只是缺路径）。对数据恢复场景已足够。

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"

	"data-recovery/internal/disk"
)

// RefsFileCandidate 从 Minstore page 里抽出的文件名候选
type RefsFileCandidate struct {
	PageOffset int64  // 所在 page 在卷里的 offset
	FileName   string // UTF-16 decode 后的文件名
	HasStream  bool   // 是否附近有 stream/extent 特征（提升置信度）
}

// ExtractFileNamesFromPage 扫一个 16KB MSB+ page 的所有 entry，抽取候选文件名。
//
// 策略（启发式）：
//   1. page header 64 字节后开始扫 entry
//   2. ReFS MSB+ entry 典型结构：offset 表 (pages 的 entry index) + 每 entry 有 size 字段 +
//      key bytes + value bytes；key 常含 UTF-16 name
//   3. 扫整 page 找"合理的 UTF-16 字符串"：
//      a. 从每个偶数 offset 尝试 decode UTF-16 LE
//      b. 合法 ASCII/BMP 字符连续 >= 2 <= 255 即采信
//      c. 过滤全 ASCII-A 之类明显垃圾模式
//
// 返回候选列表（可能有重复或假阳性；上层去重 + NSRL 过滤）。
func ExtractFileNamesFromPage(reader disk.DiskReader, pageOffset int64) ([]RefsFileCandidate, error) {
	buf := make([]byte, MinstorePageSize)
	n, err := reader.ReadAt(buf, pageOffset)
	if err != nil || int64(n) < MinstorePageSize {
		return nil, err
	}

	var out []RefsFileCandidate
	// 跳过 64 字节 header 后，每 2 字节一个 UTF-16 code unit 尝试
	for i := 64; i+4 < len(buf); i += 2 {
		name := tryDecodeUTF16Name(buf[i:])
		if name == "" {
			continue
		}
		out = append(out, RefsFileCandidate{
			PageOffset: pageOffset,
			FileName:   name,
		})
		// 跳过该字符串长度，避免相邻 offset 重复匹配
		i += len(name) * 2
	}
	return out, nil
}

// tryDecodeUTF16Name 从 b 开头尝试 decode UTF-16 LE 字符串，长度 2..255 合法才返回
func tryDecodeUTF16Name(b []byte) string {
	const minLen = 2
	const maxLen = 255
	var units []uint16
	for i := 0; i+2 <= len(b) && len(units) < maxLen; i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break // NUL 终止
		}
		// 合理字符：BMP 打印字符 + ASCII 可见 + CJK 常用区
		if !isValidNameChar(u) {
			return ""
		}
		units = append(units, u)
	}
	if len(units) < minLen {
		return ""
	}
	// 进一步启发：全是相同字符 / 明显模式 → 拒（如 "AAAAAAA"）
	if !looksLikeMeaningfulName(units) {
		return ""
	}
	name := string(utf16.Decode(units))
	// 不含 ReFS 保留字或 system prefix
	if bytes.HasPrefix([]byte(name), []byte("$")) {
		return ""
	}
	return name
}

// isValidNameChar Windows 文件名合法字符集 + 常见 Unicode 块
func isValidNameChar(u uint16) bool {
	// 控制字符禁
	if u < 0x20 {
		return false
	}
	// Windows 非法
	switch u {
	case '<', '>', ':', '"', '/', '\\', '|', '?', '*':
		return false
	}
	// ASCII 可见 + Latin-1 + 汉字 + 日文 + 韩文 + 西里尔 + 希腊 等常见
	if u <= 0x7E {
		return true
	}
	if u >= 0xA0 && u <= 0x1FFF {
		return true // Latin-1 extended / 欧洲各语种
	}
	if u >= 0x3040 && u <= 0x33FF {
		return true // 日文假名 + 部首
	}
	if u >= 0x4E00 && u <= 0x9FFF {
		return true // CJK 统一汉字
	}
	if u >= 0xAC00 && u <= 0xD7AF {
		return true // 韩文音节
	}
	if u >= 0xF900 && u <= 0xFAFF {
		return true // CJK 兼容汉字
	}
	// 其他当前拒（降假阳性）
	return false
}

// looksLikeMeaningfulName 过滤"全相同字符"等明显随机垃圾
func looksLikeMeaningfulName(units []uint16) bool {
	if len(units) < 2 {
		return false
	}
	// 统计 distinct chars
	seen := map[uint16]bool{}
	for _, u := range units {
		seen[u] = true
		if len(seen) > 2 {
			return true
		}
	}
	// 3+ 个字符都不同 → 大概率有意义
	// 否则（all same / 2 alternating）→ 垃圾
	return false
}

// EnumerateReFSFiles 扫整个 ReFS 卷所有 Minstore page，抽候选文件名。
// 适合"快速列出 ReFS 卷看上去有啥" —— 数据恢复场景够用。
//
// 不做目录树还原（ReFS 需要 object-table + 反向引用遍历），只给扁平列表。
func EnumerateReFSFiles(reader disk.DiskReader, volStart, volSize int64) ([]RefsFileCandidate, error) {
	pages, err := IndexMinstorePages(reader, volStart, volSize)
	if err != nil {
		return nil, err
	}
	var all []RefsFileCandidate
	seen := map[string]bool{}
	for _, p := range pages {
		if p.Magic != pageMagicMSBPlus {
			continue
		}
		cands, err := ExtractFileNamesFromPage(reader, p.Offset)
		if err != nil {
			continue
		}
		for _, c := range cands {
			if seen[c.FileName] {
				continue
			}
			seen[c.FileName] = true
			all = append(all, c)
		}
	}
	return all, nil
}
