//go:build windows

package disk

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows NVMe SMART —— 走 IOCTL_STORAGE_PROTOCOL_COMMAND 发 NVMe Admin
// "Get Log Page" (Opcode 0x02), Log Identifier 0x02 (SMART/Health Info)。
//
// 之前 smart_windows.go 只走 ATA SMART (IOCTL_STORAGE_PREDICT_FAILURE +
// SMART_RCV_DRIVE_DATA) —— NVMe 盘根本不支持 ATA SMART IOCTL，所以本工具对
// 所有 NVMe SSD 都报 "硬件限制，非软件 bug"，但 CrystalDiskInfo 等工具实测能
// 读到 SMART —— 它们用的就是 NVMe IOCTL 路径。本文件补上。
//
// 关键 IOCTL：
//   IOCTL_STORAGE_QUERY_PROPERTY     = 0x002D1400 (用 BusType 探 NVMe vs ATA)
//   IOCTL_STORAGE_PROTOCOL_COMMAND   = 0x002DD3C0 (发 NVMe Admin 命令)
//
// 关键 NVMe 常量（NVM Express 1.4 spec）：
//   Admin Opcode 0x02 = Get Log Page
//   LID 0x02          = SMART/Health Information
//   NSID 0xFFFFFFFF   = Controller-wide (broadcast)
//   Returned data     = 512 bytes (128 dwords)

const (
	ioctlStorageQueryProperty   uint32 = 0x002D1400
	ioctlStorageProtocolCommand uint32 = 0x002DD3C0

	// STORAGE_PROPERTY_QUERY
	storagePropertyIDAdapter = 1 // StorageAdapterProperty
	storageQueryStandard     = 0 // PropertyStandardQuery

	// STORAGE_PROTOCOL_COMMAND 字段
	storageProtocolVersion1 = 1 // STORAGE_PROTOCOL_STRUCTURE_VERSION_1
	storageProtocolTypeNvme = 3 // ProtocolTypeNvme
	storageProtoSpecNvmeAdm = 1 // STORAGE_PROTOCOL_SPECIFIC_NVME_ADMIN_COMMAND

	// BusType 枚举（ntddstor.h）
	busTypeNvme = 17 // BusTypeNvme

	// 缓冲区布局
	nvmeStorageProtoHeaderSize = 80  // sizeof STORAGE_PROTOCOL_COMMAND
	nvmeAdminCmdSize           = 64  // sizeof NVMe Submission Queue Entry
	nvmeLogSmartSize           = 512 // bytes returned for SMART/Health log

	// NVMe Get Log Page 命令字段
	nvmeOpcodeGetLogPage = 0x02
	nvmeLIDSmartHealth   = 0x02
	nvmeNSIDBroadcast    = 0xFFFFFFFF
)

// storagePropertyQuery —— IOCTL_STORAGE_QUERY_PROPERTY 输入
type storagePropertyQuery struct {
	PropertyID           uint32
	QueryType            uint32
	AdditionalParameters [1]byte
}

// storageAdapterDescriptorPrefix —— 我们只关心前面几个字段（BusType）
//
// 完整结构体很长（包含 SrbType / AddressType / BusMajorVersion / 等），
// 但我们只读到 BusType 就够了。Windows 会写入实际大小到 Size 字段，
// 我们 read partial 不影响后续字段。
type storageAdapterDescriptorPrefix struct {
	Version               uint32
	Size                  uint32
	MaximumTransferLength uint32
	MaximumPhysicalPages  uint32
	AlignmentMask         uint32
	AdapterUsesPio        byte
	AdapterScansDown      byte
	CommandQueueing       byte
	AcceleratedTransfer   byte
	BusType               byte
	// 后面还有 BusMajorVersion / BusMinorVersion / SrbType / AddressType
	// —— 我们用不上，所以这里截断。
}

// isNVMeDrive 通过 IOCTL_STORAGE_QUERY_PROPERTY 查 BusType。
// 仅当确凿是 NVMe 返回 true；查不到 / 出错都返回 false（保守，走 ATA fallback）。
func isNVMeDrive(hFile windows.Handle) bool {
	q := storagePropertyQuery{
		PropertyID: storagePropertyIDAdapter,
		QueryType:  storageQueryStandard,
	}
	var desc storageAdapterDescriptorPrefix
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		hFile,
		ioctlStorageQueryProperty,
		(*byte)(unsafe.Pointer(&q)), uint32(unsafe.Sizeof(q)),
		(*byte)(unsafe.Pointer(&desc)), uint32(unsafe.Sizeof(desc)),
		&bytesReturned, nil,
	); err != nil {
		return false
	}
	// 至少读到 BusType 才算
	if bytesReturned < uint32(unsafe.Offsetof(desc.BusType))+1 {
		return false
	}
	return desc.BusType == busTypeNvme
}

// buildNVMeGetLogPageBuffer 按 STORAGE_PROTOCOL_COMMAND + NVMe Admin
// Submission Queue Entry 布局造一个完整 IOCTL 输入缓冲区。
//
// 缓冲区布局：
//
//	[0..79]   STORAGE_PROTOCOL_COMMAND header (80B)
//	[80..143] NVMe Admin Command (64B)
//	[144..655] Data return area (512B for SMART/Health Log)
//
// 抽成独立函数，让 OS-agnostic UT 能直接验证字节布局。
func buildNVMeGetLogPageBuffer(lid byte, nsid uint32) []byte {
	const totalSize = nvmeStorageProtoHeaderSize + nvmeAdminCmdSize + nvmeLogSmartSize
	buf := make([]byte, totalSize)

	// ---- STORAGE_PROTOCOL_COMMAND header ----
	binary.LittleEndian.PutUint32(buf[0:4], storageProtocolVersion1)    // Version
	binary.LittleEndian.PutUint32(buf[4:8], nvmeStorageProtoHeaderSize) // Length (header only)
	binary.LittleEndian.PutUint32(buf[8:12], storageProtocolTypeNvme)   // ProtocolType
	binary.LittleEndian.PutUint32(buf[12:16], 0)                        // Flags
	binary.LittleEndian.PutUint32(buf[16:20], 0)                        // ReturnStatus (out)
	binary.LittleEndian.PutUint32(buf[20:24], 0)                        // ErrorCode (out)
	binary.LittleEndian.PutUint32(buf[24:28], nvmeAdminCmdSize)         // CommandLength
	binary.LittleEndian.PutUint32(buf[28:32], 0)                        // ErrorInfoLength
	binary.LittleEndian.PutUint32(buf[32:36], 0)                        // DataToDeviceTransferLength
	binary.LittleEndian.PutUint32(buf[36:40], nvmeLogSmartSize)         // DataFromDeviceTransferLength
	binary.LittleEndian.PutUint32(buf[40:44], 10)                       // TimeOutValue (seconds)
	binary.LittleEndian.PutUint32(buf[44:48], 0)                        // ErrorInfoOffset
	binary.LittleEndian.PutUint32(buf[48:52], 0)                        // DataToDeviceBufferOffset
	binary.LittleEndian.PutUint32(buf[52:56],
		nvmeStorageProtoHeaderSize+nvmeAdminCmdSize) // DataFromDeviceBufferOffset
	binary.LittleEndian.PutUint32(buf[56:60], storageProtoSpecNvmeAdm) // CommandSpecific

	// ---- NVMe Admin Submission Queue Entry (64 bytes) at offset 80 ----
	cmdOff := nvmeStorageProtoHeaderSize
	buf[cmdOff+0] = nvmeOpcodeGetLogPage // OPC = 0x02 (Get Log Page)
	// byte 1 (FUSE/PSDT) = 0, bytes 2-3 (CID) = 0
	binary.LittleEndian.PutUint32(buf[cmdOff+4:cmdOff+8], nsid) // NSID
	// MPTR / PRP1 / PRP2 (bytes 16..39 within command) 全 0；驱动会自己设
	// CDW10: bits 31:16 = NUMDL (number of dwords lower, 0-based), bits 15:8 = LSP, bits 7:0 = LID
	numd := uint32(nvmeLogSmartSize/4) - 1 // 128 dwords - 1 = 127 = 0x7F
	cdw10 := (numd << 16) | uint32(lid)
	binary.LittleEndian.PutUint32(buf[cmdOff+40:cmdOff+44], cdw10)
	// CDW11..CDW15 全 0

	return buf
}

// querySmartNVMeWindows 用 NVMe Get Log Page 拿 SMART/Health。
// hFile 必须是物理盘 handle（不能是逻辑卷）。
func querySmartNVMeWindows(hFile windows.Handle) *SmartHealth {
	buf := buildNVMeGetLogPageBuffer(nvmeLIDSmartHealth, nvmeNSIDBroadcast)

	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		hFile,
		ioctlStorageProtocolCommand,
		&buf[0], uint32(len(buf)),
		&buf[0], uint32(len(buf)),
		&bytesReturned, nil,
	); err != nil {
		return nil
	}

	// ReturnStatus 在 header offset 16 —— 非 0 表示 NVMe 命令失败（CRC / NSID / etc.）
	returnStatus := binary.LittleEndian.Uint32(buf[16:20])
	if returnStatus != 0 {
		return nil
	}

	// 数据从 DataFromDeviceBufferOffset 开始（80 + 64 = 144）
	dataOff := nvmeStorageProtoHeaderSize + nvmeAdminCmdSize
	if len(buf) < dataOff+nvmeLogSmartSize {
		return nil
	}
	log := buf[dataOff : dataOff+nvmeLogSmartSize]

	h := parseNVMeSmartHealthLog(log)
	if h != nil {
		h.Available = true
		h.Source = "native-nvme"
	}
	return h
}
