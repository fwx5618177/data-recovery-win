//go:build windows

package disk

import (
	"context"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows 原生 SMART：DeviceIoControl + IOCTL_STORAGE_PREDICT_FAILURE +
// SMART_RCV_DRIVE_DATA。不需要 cgo，复用包内已用的 golang.org/x/sys/windows。
//
// 微软 IOCTL（winioctl.h）：
//   IOCTL_STORAGE_PREDICT_FAILURE = 0x002D1100
//     —— 给 PASS/FAIL 预测 + 512 字节 vendor data（SATA 上就是 SMART attribute table）
//   SMART_RCV_DRIVE_DATA          = 0x0007C088
//     —— ATA SMART READ DATA / IDENTIFY DEVICE 命令；用 SENDCMDINPARAMS / SENDCMDOUTPARAMS

const (
	ioctlStoragePredictFailure uint32 = 0x002D1100
	smartRcvDriveData          uint32 = 0x0007C088
)

// IDEREGS（ntdddisk.h）—— ATA 寄存器 8 字节
type ideRegs struct {
	bFeaturesReg     byte
	bSectorCountReg  byte
	bSectorNumberReg byte
	bCylLowReg       byte
	bCylHighReg      byte
	bDriveHeadReg    byte
	bCommandReg      byte
	bReserved        byte
}

// SENDCMDINPARAMS —— 输入；bBuffer 是变长占位（实际内联 512 字节用底下 byte slice 自补）
type sendCmdInParams struct {
	cBufferSize  uint32
	irDriveRegs  ideRegs
	bDriveNumber byte
	bReserved    [3]byte
	dwReserved   [4]uint32
	bBuffer      [1]byte
}

// SENDCMDOUTPARAMS —— 输出，含 driverStatus + 512 字节数据
type sendCmdOutParams struct {
	cBufferSize  uint32
	driverStatus [8]byte
	bBuffer      [512]byte
}

// STORAGE_PREDICT_FAILURE
type storagePredictFailure struct {
	PredictFailure uint32
	VendorSpecific [512]byte
}

// querySmartNative 是 Windows 实现。
//
// devicePath 三种形态都吃：
//   - `\\.\PhysicalDrive0` —— 直接打开
//   - `\\.\G:`              —— **逻辑卷**，先解析出底层物理盘索引再重定向
//   - `disk0` / `0`         —— 索引数字补成 PhysicalDrive
//
// SMART IOCTL 只能在物理盘 handle 上跑，逻辑卷会失败 —— 所以必须先解析。
//
// v2.8.39 路由：先用 IOCTL_STORAGE_QUERY_PROPERTY 探 BusType，**NVMe 走
// NVMe Get Log Page，ATA/SATA 走旧 PREDICT_FAILURE 路径**。之前所有盘都走
// ATA SMART，NVMe SSD 100% 失败，CrystalDiskInfo 能读但本工具说"硬件限制"。
//
// USB 桥接 SATA 盘多数不透传 SMART，会得到失败错误，写入 Notes 让用户知情。
func querySmartNative(_ context.Context, devicePath string) *SmartHealth {
	winPath := resolveToPhysicalDriveWindows(devicePath)
	if winPath == "" {
		return nil
	}
	pUTF16, err := windows.UTF16PtrFromString(winPath)
	if err != nil {
		return nil
	}
	hFile, err := windows.CreateFile(
		pUTF16,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(hFile)

	// v2.8.39: NVMe 路径
	if isNVMeDrive(hFile) {
		if h := querySmartNVMeWindows(hFile); h != nil && h.Available {
			// NVMe 没有 IDENTIFY DEVICE (ATA) —— Model/Serial 走 STORAGE_DEVICE_DESCRIPTOR
			if model, serial := readNVMeModelSerial(hFile); model != "" || serial != "" {
				h.Model = model
				h.Serial = serial
			}
			return h
		}
		// NVMe 探到了但 SMART 读失败 —— 不再 fall through 到 ATA（NVMe 盘根本不支持 ATA SMART，
		// 继续尝试只会浪费 IOCTL + 让用户看到误导性的 "硬件限制" 消息）。返回不可用，
		// 上层 QuerySmart 会拿到 nil → 走 unavailableHint。
		return nil
	}

	// ATA / SATA 路径 —— 旧 PREDICT_FAILURE 实现
	var pf storagePredictFailure
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		hFile,
		ioctlStoragePredictFailure,
		nil, 0,
		(*byte)(unsafe.Pointer(&pf)), uint32(unsafe.Sizeof(pf)),
		&bytesReturned, nil,
	); err != nil {
		return nil
	}
	h := parseATASmartData(pf.VendorSpecific[:])
	if h == nil || !h.Available {
		return nil
	}
	if pf.PredictFailure != 0 {
		h.Healthy = false
	}
	h.Source = "native"

	// IDENTIFY DEVICE 拿 model / serial
	if model, serial := readIdentifyWindows(hFile); model != "" || serial != "" {
		h.Model = model
		h.Serial = serial
	}
	return h
}

// readNVMeModelSerial 通过 IOCTL_STORAGE_QUERY_PROPERTY 拿 NVMe 盘的 Model / Serial。
//
// 用 StorageDeviceProperty (= 0) 拿 STORAGE_DEVICE_DESCRIPTOR，
// 里头有 ProductIdOffset / SerialNumberOffset 指向字符串。
//
// 用 1KB 缓冲区接收（descriptor 主体 + trailing 字符串）。
func readNVMeModelSerial(hFile windows.Handle) (string, string) {
	q := storagePropertyQuery{
		PropertyID: 0, // StorageDeviceProperty
		QueryType:  storageQueryStandard,
	}
	var buf [1024]byte
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		hFile,
		ioctlStorageQueryProperty,
		(*byte)(unsafe.Pointer(&q)), uint32(unsafe.Sizeof(q)),
		&buf[0], uint32(len(buf)),
		&bytesReturned, nil,
	); err != nil {
		return "", ""
	}
	if bytesReturned < 36 {
		return "", ""
	}
	// STORAGE_DEVICE_DESCRIPTOR 字段偏移：
	//   ProductIdOffset    @ offset 8 (DWORD)
	//   SerialNumberOffset @ offset 24 (DWORD)
	productOff := uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24
	serialOff := uint32(buf[24]) | uint32(buf[25])<<8 | uint32(buf[26])<<16 | uint32(buf[27])<<24

	readCString := func(off uint32) string {
		if off == 0 || off >= bytesReturned {
			return ""
		}
		end := off
		for end < bytesReturned && buf[end] != 0 {
			end++
		}
		return strings.TrimSpace(string(buf[off:end]))
	}
	return readCString(productOff), readCString(serialOff)
}

// readIdentifyWindows 通过 SMART_RCV_DRIVE_DATA 发 IDENTIFY DEVICE (0xEC)
func readIdentifyWindows(hFile windows.Handle) (string, string) {
	const inSize = uint32(unsafe.Sizeof(sendCmdInParams{})) + 511 // bBuffer 占位补到 512
	in := make([]byte, inSize)
	inP := (*sendCmdInParams)(unsafe.Pointer(&in[0]))
	inP.cBufferSize = 512
	inP.irDriveRegs.bSectorCountReg = 1
	inP.irDriveRegs.bCommandReg = 0xEC // IDENTIFY DEVICE

	const outSize = uint32(unsafe.Sizeof(sendCmdOutParams{}))
	out := make([]byte, outSize)
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		hFile,
		smartRcvDriveData,
		&in[0], inSize,
		&out[0], outSize,
		&bytesReturned, nil,
	); err != nil {
		return "", ""
	}
	outP := (*sendCmdOutParams)(unsafe.Pointer(&out[0]))
	// IDENTIFY DEVICE 数据：
	//   word 10-19 (byte 20-39): Serial
	//   word 27-46 (byte 54-93): Model
	serial := ataSwapStringWindows(outP.bBuffer[20 : 20+20])
	model := ataSwapStringWindows(outP.bBuffer[54 : 54+40])
	return model, serial
}

// ataSwapStringWindows IDENTIFY DEVICE 字符串字段是 16 位字节交换 + 末尾空格 padding
func ataSwapStringWindows(b []byte) string {
	out := make([]byte, len(b))
	for i := 0; i+1 < len(b); i += 2 {
		out[i] = b[i+1]
		out[i+1] = b[i]
	}
	return strings.TrimSpace(string(out))
}

// tryParseDriveIndex 从 "disk0" / "physicaldrive0" / "0" 提取数字
func tryParseDriveIndex(s string) int {
	s = strings.ToLower(s)
	for _, prefix := range []string{`\\.\physicaldrive`, "physicaldrive", "disk"} {
		if strings.HasPrefix(s, prefix) {
			rest := s[len(prefix):]
			if n, err := strconv.Atoi(rest); err == nil {
				return n
			}
		}
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return -1
}
