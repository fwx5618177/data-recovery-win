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

// isNVMeDrive 通过 IOCTL_STORAGE_QUERY_PROPERTY 查 BusType。
// 仅当确凿是 NVMe 返回 true；查不到 / 出错都返回 false（保守，走 ATA fallback）。
//
// v2.8.40: 用 128 字节 ouput 缓冲，避免某些驱动写入完整 STORAGE_ADAPTER_DESCRIPTOR
// （>28 字节）时 BytesReturned 被截断或被报 ERROR_INSUFFICIENT_BUFFER。
// 加日志：失败时把 Windows error code + bytesReturned + BusType 都打出来，
// 让用户排错时能告诉我们究竟发生了什么。
func isNVMeDrive(hFile windows.Handle) bool {
	q := storagePropertyQuery{
		PropertyID: storagePropertyIDAdapter,
		QueryType:  storageQueryStandard,
	}
	// 128B 足够容纳全 STORAGE_ADAPTER_DESCRIPTOR（实际 ~36–48B），buffer 大点不亏。
	var out [128]byte
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		hFile,
		ioctlStorageQueryProperty,
		(*byte)(unsafe.Pointer(&q)), uint32(unsafe.Sizeof(q)),
		&out[0], uint32(len(out)),
		&bytesReturned, nil,
	); err != nil {
		smartLogger.Warn("BusType 探测失败（IOCTL_STORAGE_QUERY_PROPERTY）",
			"err", err, "bytesReturned", bytesReturned)
		return false
	}
	// BusType 是 STORAGE_ADAPTER_DESCRIPTOR 的第 25 字节（offset 24）
	const busTypeOffset = 24
	if bytesReturned < busTypeOffset+1 {
		smartLogger.Warn("BusType 探测返回数据过短", "bytesReturned", bytesReturned)
		return false
	}
	bt := out[busTypeOffset]
	smartLogger.Debug("BusType 探测", "busType", bt, "isNVMe", bt == busTypeNvme,
		"bytesReturned", bytesReturned)
	return bt == busTypeNvme
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
//
// v2.8.40: 每条失败路径都打 Warn 日志（IOCTL 错误码 / ReturnStatus / 缓冲不足），
// 让用户排错时能把日志贴回来定位问题。常见失败：
//   - 0x00000005 (ERROR_ACCESS_DENIED) → 没以管理员运行
//   - 0x00000001 (ERROR_INVALID_FUNCTION) → 驱动不支持 protocol-specific 命令
//   - 0x00000031 (ERROR_NOT_SUPPORTED) → 老 Windows 内核不支持该 IOCTL（< Win 10 1709）
//   - ReturnStatus != 0 → 驱动转发但 NVMe 控制器拒绝命令
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
		smartLogger.Warn("NVMe Get Log Page IOCTL 失败",
			"err", err,
			"bytesReturned", bytesReturned,
			"hint", nvmeIOCTLErrorHint(err))
		return nil
	}

	// ReturnStatus 在 header offset 16 —— 非 0 表示 NVMe 命令失败（CRC / NSID / etc.）
	returnStatus := binary.LittleEndian.Uint32(buf[16:20])
	if returnStatus != 0 {
		errorCode := binary.LittleEndian.Uint32(buf[20:24])
		smartLogger.Warn("NVMe 控制器拒绝 Get Log Page",
			"returnStatus", returnStatus,
			"errorCode", errorCode,
			"hint", "驱动转发但控制器拒绝；可能是 LSP / NSID 不被该控制器支持")
		return nil
	}

	// 数据从 DataFromDeviceBufferOffset 开始（80 + 64 = 144）
	dataOff := nvmeStorageProtoHeaderSize + nvmeAdminCmdSize
	if len(buf) < dataOff+nvmeLogSmartSize {
		smartLogger.Warn("NVMe SMART log 返回数据不足", "len", len(buf), "expected", dataOff+nvmeLogSmartSize)
		return nil
	}
	log := buf[dataOff : dataOff+nvmeLogSmartSize]

	h := parseNVMeSmartHealthLog(log)
	if h != nil {
		h.Available = true
		h.Source = "native-nvme"
		smartLogger.Info("NVMe SMART 读取成功",
			"healthy", h.Healthy,
			"temp", h.Temperature,
			"powerOnHours", h.PowerOnHours,
			"mediaErrors", h.UncorrectableErrors)
	}
	return h
}

// nvmeIOCTLErrorHint 把常见 Windows 错误码翻译成"用户能看懂的中文原因"，
// 写进日志方便用户贴回来排错。日志比 toast 详细 —— 这里专给开发者看。
func nvmeIOCTLErrorHint(err error) string {
	if err == nil {
		return ""
	}
	switch err {
	case windows.ERROR_ACCESS_DENIED:
		return "没以管理员权限运行（必须 elevated 才能调 PhysicalDrive IOCTL）"
	case windows.ERROR_INVALID_FUNCTION:
		return "驱动不支持 IOCTL_STORAGE_PROTOCOL_COMMAND（多见于 OEM 笔记本预装的厂商 NVMe 驱动）"
	case windows.ERROR_NOT_SUPPORTED:
		return "Windows 内核不支持该 IOCTL（需 Windows 10 1709 以上）"
	case windows.ERROR_INSUFFICIENT_BUFFER:
		return "输出缓冲过小（理论不应发生 —— 我们传了 656B 远超 NVMe SMART log 所需）"
	}
	return ""
}
