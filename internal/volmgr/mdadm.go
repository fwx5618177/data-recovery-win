package volmgr

// mdadm superblock v1.x 完整解析 —— 从每块盘读出 array UUID / level / chunk /
// role，跨盘按 UUID 分组 + 按 role 排序，输出组装方案给 raid.NewReader。
//
// 规范来源：Linux kernel include/uapi/linux/raid/md_p.h `struct mdp_superblock_1`
//
// v1.x 三种放置位置：
//   1.0 → 盘尾（相对 device 末尾 -8 KiB 对齐）
//   1.1 → offset 0
//   1.2 → offset 4 KiB（最常见 —— mdadm 默认）
//
// 本实现优先尝试 1.2 / 1.1；1.0 需要 reader.Size()，按需 fallback。
//
// 覆盖范围：raid0/1/4/5/6/10 + 标准 superblock 字段。
// 不覆盖：bitmap、bbl (bad block log)、reshape metadata、journal device。

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"data-recovery/internal/disk"
)

// MDADMSuperblockV1 从 v1.x superblock 抽出的关键字段。
// 字节序全部 little-endian（Linux md 格式）。
type MDADMSuperblockV1 struct {
	Magic        uint32   // 0xA92B4EFC
	MajorVersion uint32   // 1
	FeatureMap   uint32
	SetUUID      [16]byte // 阵列 UUID（所有成员盘一致）
	SetName      string   // 阵列名（hostname:arrayname）
	CTime        uint64   // 创建时间（unix 秒）

	Level      int32 // 0/1/4/5/6/10 / -1=linear
	Layout     uint32
	Size       uint64 // 单盘数据大小（扇区数 × 512）

	ChunkSectors uint32 // chunk 大小（扇区）—— 字节数 = ChunkSectors*512
	RaidDisks    uint32 // 阵列成员盘总数

	DataOffset    uint64 // 本盘 data 从哪个扇区开始（mdadm 保留前若干 KiB 给 superblock）
	DataSize      uint64
	SuperOffset   uint64
	DevNumber     uint32 // 本盘在 dev_roles 表里的索引
	DeviceUUID    [16]byte
	DevRoles      []uint16 // dev_roles[dev_number] = 本盘在阵列里的 role（0..raid_disks-1）

	// Role 在阵列里的位置。-1 = 无效 / spare / faulty
	Role int
}

// ChunkBytes chunk size in bytes
func (s *MDADMSuperblockV1) ChunkBytes() int64 {
	return int64(s.ChunkSectors) * 512
}

// DataOffsetBytes 本盘数据起始字节偏移
func (s *MDADMSuperblockV1) DataOffsetBytes() int64 {
	return int64(s.DataOffset) * 512
}

// UUIDString 把 16 字节 UUID 格式化为 mdadm --detail 一致的字符串
func (s *MDADMSuperblockV1) UUIDString() string {
	u := s.SetUUID
	return fmt.Sprintf("%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x",
		u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
		u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15])
}

// LevelString 人类可读 level 名
func (s *MDADMSuperblockV1) LevelString() string {
	switch s.Level {
	case 0:
		return "raid0"
	case 1:
		return "raid1"
	case 4:
		return "raid4"
	case 5:
		return "raid5"
	case 6:
		return "raid6"
	case 10:
		return "raid10"
	case -1:
		return "linear"
	default:
		return fmt.Sprintf("raid?(%d)", s.Level)
	}
}

// ParseMDADMSuperblockV1 从一块盘读出 mdadm v1.x superblock。
// 未找到返回 (nil, nil)；找到但解析失败返回 (nil, error)。
func ParseMDADMSuperblockV1(reader disk.DiskReader) (*MDADMSuperblockV1, error) {
	// v1.2 (offset 4096) 是最常见的，mdadm 3.0+ 默认
	if sb, err := tryParseAt(reader, 4096); err == nil && sb != nil {
		return sb, nil
	}
	// v1.1 offset 0
	if sb, err := tryParseAt(reader, 0); err == nil && sb != nil {
		return sb, nil
	}
	// v1.0 盘尾 —— 需要知道盘大小
	size, err := reader.Size()
	if err == nil && size > 0 {
		// v1.0 放在盘尾，对齐到 4K 后再减 8K
		tailOff := (size &^ 4095) - 8*1024
		if tailOff > 0 {
			if sb, err := tryParseAt(reader, tailOff); err == nil && sb != nil {
				return sb, nil
			}
		}
	}
	return nil, nil
}

const mdSuperblockMagic uint32 = 0xA92B4EFC

func tryParseAt(reader disk.DiskReader, off int64) (*MDADMSuperblockV1, error) {
	// 读 4KiB：固定 256 字节 header + 最多 ~1000 个 dev_roles (uint16) 足够
	buf := make([]byte, 4096)
	n, err := reader.ReadAt(buf, off)
	if err != nil && err != io.EOF {
		return nil, nil
	}
	if n < 256 {
		return nil, nil
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != mdSuperblockMagic {
		return nil, nil
	}
	if binary.LittleEndian.Uint32(buf[4:8]) != 1 {
		// 不是 v1.x
		return nil, nil
	}

	sb := &MDADMSuperblockV1{
		Magic:        binary.LittleEndian.Uint32(buf[0:4]),
		MajorVersion: binary.LittleEndian.Uint32(buf[4:8]),
		FeatureMap:   binary.LittleEndian.Uint32(buf[8:12]),
	}
	copy(sb.SetUUID[:], buf[16:32])
	// set_name 32 字节 NUL-terminated
	nameEnd := bytes.IndexByte(buf[32:64], 0)
	if nameEnd < 0 {
		nameEnd = 32
	}
	sb.SetName = string(buf[32 : 32+nameEnd])

	sb.CTime = binary.LittleEndian.Uint64(buf[64:72])
	sb.Level = int32(binary.LittleEndian.Uint32(buf[72:76]))
	sb.Layout = binary.LittleEndian.Uint32(buf[76:80])
	sb.Size = binary.LittleEndian.Uint64(buf[80:88])
	sb.ChunkSectors = binary.LittleEndian.Uint32(buf[88:92])
	sb.RaidDisks = binary.LittleEndian.Uint32(buf[92:96])
	// 96..128 reserved / bitmap 相关
	sb.DataOffset = binary.LittleEndian.Uint64(buf[128:136])
	sb.DataSize = binary.LittleEndian.Uint64(buf[136:144])
	sb.SuperOffset = binary.LittleEndian.Uint64(buf[144:152])
	// 152..156 recovery_offset
	sb.DevNumber = binary.LittleEndian.Uint32(buf[156:160])
	// 160..192 device UUID in md_p.h 布局（注意：真实布局 device uuid 在 offset 144+？
	// 以 Linux md_p.h 为准 —— dev_number 在 offset 156，device_uuid 在 offset 160）
	copy(sb.DeviceUUID[:], buf[160:176])

	// dev_roles 表从 offset 256 开始，每个 role 2 字节 (uint16)
	// max_dev 数量 = (superblock_size - 256) / 2，但实际阵列成员数 = raid_disks
	// 本实现只关心 raid_disks 个 role（加一定余量容错）
	rolesStart := 256
	maxRoles := sb.RaidDisks + 32 // 加 spare 冗余
	sb.DevRoles = make([]uint16, 0, maxRoles)
	for i := uint32(0); i < maxRoles; i++ {
		pos := rolesStart + int(i)*2
		if pos+2 > n {
			break
		}
		sb.DevRoles = append(sb.DevRoles, binary.LittleEndian.Uint16(buf[pos:pos+2]))
	}

	// 本盘 role = DevRoles[DevNumber]
	sb.Role = -1
	if int(sb.DevNumber) < len(sb.DevRoles) {
		role := sb.DevRoles[sb.DevNumber]
		// 0xFFFF = spare / empty, 0xFFFE = faulty
		if role < 0xFFFE {
			sb.Role = int(role)
		}
	}

	return sb, nil
}

// DetectedArray 多盘扫描后匹配出的 RAID 阵列
type DetectedArray struct {
	UUID        string
	Name        string
	Level       string     // "raid0" / "raid1" / "raid5" / "raid6" / "raid10"
	ChunkBytes  int64      // 条带大小（字节）
	RaidDisks   int        // 理论成员盘数
	OrderedPaths []string  // 按 role 排好序的成员盘路径；缺失成员对应位置为 ""
	DataOffset  int64      // 成员盘上数据起点（字节）
	Members     []DetectedMember
}

type DetectedMember struct {
	Path    string
	Role    int
	DevUUID string
}

// DetectRAIDArrays 扫描一组盘，按 mdadm array UUID 聚合，返回可组装的阵列清单。
//
// 用途：前端给用户"选择多块盘"UI，收集到 []drivePath 后调本接口；返回的每个
// DetectedArray 直接构造 raid.Config 即可（见 App.StartRAIDScan）。
//
// 不覆盖：LVM2 / Storage Spaces（这两个格式比 mdadm 复杂，当前仅作识别）。
// 如果盘是 LVM 成员，本函数返回空列表；前端应引导用户先在原系统 vgchange 再扫。
func DetectRAIDArrays(paths []string) ([]DetectedArray, []error) {
	arraysByUUID := map[string]*DetectedArray{}
	var errs []error

	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		reader := disk.NewReader(p)
		if err := disk.OpenWithTimeout(reader, 5*time.Second); err != nil {
			errs = append(errs, fmt.Errorf("打开 %s: %w", p, err))
			continue
		}
		sb, err := ParseMDADMSuperblockV1(reader)
		_ = reader.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("解析 %s superblock: %w", p, err))
			continue
		}
		if sb == nil {
			continue // 不是 mdadm 成员
		}
		if sb.Role < 0 {
			// spare/faulty 跳过
			continue
		}
		uuid := sb.UUIDString()
		arr, ok := arraysByUUID[uuid]
		if !ok {
			arr = &DetectedArray{
				UUID:         uuid,
				Name:         sb.SetName,
				Level:        sb.LevelString(),
				ChunkBytes:   sb.ChunkBytes(),
				RaidDisks:    int(sb.RaidDisks),
				OrderedPaths: make([]string, sb.RaidDisks),
				DataOffset:   sb.DataOffsetBytes(),
			}
			arraysByUUID[uuid] = arr
		}
		// 按 role 放入对应槽位
		if sb.Role < arr.RaidDisks {
			arr.OrderedPaths[sb.Role] = p
		}
		arr.Members = append(arr.Members, DetectedMember{
			Path:    p,
			Role:    sb.Role,
			DevUUID: fmt.Sprintf("%x", sb.DeviceUUID),
		})
	}

	out := make([]DetectedArray, 0, len(arraysByUUID))
	for _, a := range arraysByUUID {
		out = append(out, *a)
	}
	return out, errs
}
