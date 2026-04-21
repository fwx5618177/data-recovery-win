package bitlocker

import (
	"encoding/binary"
	"fmt"
)

// FVE Metadata Block 内部用一棵"datum 树"组织所有元数据：
// VMK / FVEK / 加密保护器（recovery key、TPM、password）等都是 datum，部分 datum 嵌套子 datum。
//
// 每个 datum 头 8 字节：
//
//	+0x00  Size       uint16  本 datum 总字节数（含头 + 本体；可能含 padding）
//	+0x02  Type       uint16  datum 类型（业务类型，见 DatumEntryType*）
//	+0x04  ValueType  uint16  本 datum 数据如何解释（见 DatumValueType*）
//	+0x06  Version    uint16  通常为 1
//
// 之后是按 ValueType 决定的 payload。Type vs ValueType 的关系：
//   - Type 说明"这个 datum 在 BitLocker 协议里扮演什么角色"
//   - ValueType 说明"载荷的字节如何 parse"
//
// 例如：一个 VMK datum 的 Type=0x2000、ValueType=0x0008（VMK 类型）、payload 是
// VMK 头部 + 嵌套的子 datum（其中含 STRETCH_KEY + AES_CCM_ENCRYPTED_KEY 等）。
//
// 参考：[MS-FVE] 协议规范 + libbde 文档（git.legrandin.com/yann/libbde）。

// DatumEntryType（业务角色 / 用途）
const (
	DatumEntryUnknown            uint16 = 0x0000
	DatumEntryProperty           uint16 = 0x0002
	DatumEntryVMKInfo            uint16 = 0x2000
	DatumEntryFVEKInfo           uint16 = 0x2002
	DatumEntryValidation         uint16 = 0x2003
	DatumEntryStartupKey         uint16 = 0x2004
	DatumEntryDescription        uint16 = 0x2005
	DatumEntryFVEKBackup         uint16 = 0x2006
	DatumEntryVolumeHeaderBlock  uint16 = 0x2007
)

// DatumValueType（载荷字节的 schema）
const (
	DatumValueErased         uint16 = 0x0000 // 未使用 / 已擦除
	DatumValueKey            uint16 = 0x0001 // 裸密钥
	DatumValueUnicodeString  uint16 = 0x0002 // UTF-16 LE 字符串
	DatumValueStretchKey     uint16 = 0x0003 // 拉伸密钥（password / recovery）
	DatumValueUse            uint16 = 0x0004 // "USE" datum，含 role 子标识
	DatumValueAESCCMKey      uint16 = 0x0005 // AES-CCM 加密的密钥（被另一个密钥包过）
	DatumValueTPMEncodedKey  uint16 = 0x0006 // TPM 封装密钥
	DatumValueValidation     uint16 = 0x0007
	DatumValueVMK            uint16 = 0x0008 // VMK 整体，包含若干 protector 子 datum
	DatumValueExternalKey    uint16 = 0x0009 // 外部密钥（startup key）
	DatumValueUpdate         uint16 = 0x000A
	DatumValueErrorLog       uint16 = 0x000B
	DatumValueOffsetSize     uint16 = 0x000F
	DatumValueRecoveryTime   uint16 = 0x0011
	DatumValueAESCCMConcat   uint16 = 0x0014 // 老版本里有时见到
)

// USE datum 的 role 标识符（"这个保护器是干什么的"），位于 USE 载荷头 4 字节
const (
	UseRoleVMK              uint32 = 0x80
	UseRoleAESCCMKey        uint32 = 0x100
	UseRoleStretchedKey     uint32 = 0x200
	// 实际还有更多，需要时再加
)

// VMK protection type（VMK datum payload 的 Protection Type 字段，2 字节）
const (
	VMKProtectionClearKey      uint16 = 0x0000 // 没保护（已解密的 VMK）
	VMKProtectionTPM           uint16 = 0x0100
	VMKProtectionStartupKey    uint16 = 0x0200
	VMKProtectionTPMAndPin     uint16 = 0x0500
	VMKProtectionRecoveryPwd   uint16 = 0x0800 // 48-digit recovery key ⭐
	VMKProtectionPassword      uint16 = 0x2000 // 用户密码
)

// Datum 是解析后的统一表示。Body 是去掉 8 字节头之后的原始载荷，
// 由调用方按 ValueType 进一步解析。
type Datum struct {
	Size      uint16 // 含 header
	Type      uint16
	ValueType uint16
	Version   uint16
	Body      []byte // size - 8 bytes
	// 嵌套子 datum 的方便访问；只有部分 ValueType 才有意义（如 VMK / USE / STRETCH_KEY）
	Children []Datum
}

// ParseDatum 从 buf 的 pos 起解析一个 datum。
// 失败返回 nil + size=0 + error；调用方应停止当前序列。
//
// 对已知会嵌套子 datum 的 ValueType（VMK / STRETCH_KEY / AES_CCM_KEY），
// 自动递归把 Children 也填上。
func ParseDatum(buf []byte, pos int) (*Datum, int, error) {
	if pos+8 > len(buf) {
		return nil, 0, fmt.Errorf("datum 头部不足: pos=%d len=%d", pos, len(buf))
	}
	d := &Datum{
		Size:      binary.LittleEndian.Uint16(buf[pos : pos+2]),
		Type:      binary.LittleEndian.Uint16(buf[pos+2 : pos+4]),
		ValueType: binary.LittleEndian.Uint16(buf[pos+4 : pos+6]),
		Version:   binary.LittleEndian.Uint16(buf[pos+6 : pos+8]),
	}
	if d.Size < 8 {
		return nil, 0, fmt.Errorf("datum size 异常: %d", d.Size)
	}
	if pos+int(d.Size) > len(buf) {
		return nil, 0, fmt.Errorf("datum size %d 超出剩余 %d", d.Size, len(buf)-pos)
	}
	d.Body = make([]byte, int(d.Size)-8)
	copy(d.Body, buf[pos+8:pos+int(d.Size)])

	// 递归解析嵌套
	if hasNestedChildren(d.ValueType) {
		hdrLen := nestedHeaderLen(d.ValueType)
		if hdrLen <= len(d.Body) {
			children, err := parseDatumList(d.Body[hdrLen:])
			if err == nil {
				d.Children = children
			}
		}
	}
	return d, int(d.Size), nil
}

// parseDatumList 把一段 buf 里所有连续 datum 一次性 parse 出来
func parseDatumList(buf []byte) ([]Datum, error) {
	var out []Datum
	pos := 0
	for pos < len(buf) {
		d, consumed, err := ParseDatum(buf, pos)
		if err != nil {
			break // 容错：尾部可能是 padding / corruption
		}
		out = append(out, *d)
		pos += consumed
		if consumed == 0 {
			break
		}
	}
	return out, nil
}

// hasNestedChildren 对哪些 ValueType 自动递归子 datum
func hasNestedChildren(vt uint16) bool {
	switch vt {
	case DatumValueVMK, DatumValueStretchKey, DatumValueAESCCMKey,
		DatumValueExternalKey, DatumValueUse, DatumValueAESCCMConcat:
		return true
	}
	return false
}

// nestedHeaderLen 不同 wrapper datum 的固定 header 长度（在子 datum 之前）
//
// VMK 头部 28 字节：
//   GUID(16) + last_change(8) + protection(2) + ?(2)
// STRETCH_KEY 头部 20 字节：
//   encryption_method(4) + salt(16)
// AES_CCM_KEY 头部 28 字节：
//   nonce_time(8) + nonce_counter(4) + mac(16)
// EXTERNAL_KEY 头部 28 字节：
//   GUID(16) + last_change(8) + ?(4)
// USE 头部 4 字节：role(uint32)
func nestedHeaderLen(vt uint16) int {
	switch vt {
	case DatumValueVMK:
		return 28
	case DatumValueStretchKey:
		return 20
	case DatumValueAESCCMKey, DatumValueAESCCMConcat:
		return 28
	case DatumValueExternalKey:
		return 28
	case DatumValueUse:
		return 4
	}
	return 0
}

// FindDatumByValueType 在一组 datum 里找第一个特定 ValueType 的（含 children 中的）
func FindDatumByValueType(datums []Datum, vt uint16) *Datum {
	for i := range datums {
		if datums[i].ValueType == vt {
			return &datums[i]
		}
		if len(datums[i].Children) > 0 {
			if c := FindDatumByValueType(datums[i].Children, vt); c != nil {
				return c
			}
		}
	}
	return nil
}

// FindAllDatumByValueType 找全部符合的（包括嵌套）
func FindAllDatumByValueType(datums []Datum, vt uint16) []*Datum {
	var out []*Datum
	for i := range datums {
		if datums[i].ValueType == vt {
			out = append(out, &datums[i])
		}
		if len(datums[i].Children) > 0 {
			out = append(out, FindAllDatumByValueType(datums[i].Children, vt)...)
		}
	}
	return out
}
