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

	// 1) PREDICT_FAILURE —— PASS/FAIL + 512 字节 vendor data
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

	// 2) IDENTIFY DEVICE 拿 model / serial
	if model, serial := readIdentifyWindows(hFile); model != "" || serial != "" {
		h.Model = model
		h.Serial = serial
	}
	return h
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
