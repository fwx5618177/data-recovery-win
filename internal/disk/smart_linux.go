//go:build linux

package disk

import (
	"context"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Linux 原生 SMART：HDIO_DRIVE_CMD ioctl 直接发 ATA SMART READ DATA 命令。
// 不需要 cgo / 第三方库。NVMe 走单独的 NVME_IOCTL_ADMIN_CMD —— 当前先支持
// SATA / IDE 老盘（数据恢复场景下最常见的就是这些有年头的盘）。
//
// 引用：linux/Documentation/ioctl/hdio.txt
//   HDIO_DRIVE_CMD = 0x031F
//   buf[0] = ATA command (SMART = 0xB0)
//   buf[1] = sector count
//   buf[2] = feature register (具体 SMART 子命令，0xD0 = READ DATA)
//   buf[3] = number of sectors transferred (1)
//   buf[4..515] = 512 字节数据缓冲区

const (
	// HDIO_DRIVE_CMD 在 32 位 / 64 位都是 0x031F（ASM-generic）
	hdioDriveCmd = 0x031F

	ataCmdSmart       = 0xB0
	ataSmartReadData  = 0xD0
	ataSmartReturnSts = 0xDA
)

// querySmartNative 是 Linux 实现。/dev/sd*、/dev/hd* 是 ATA 设备；
// /dev/nvme* 暂时返回 nil 让 fallback 接手（NVMe 单独的 admin command 协议）。
func querySmartNative(ctx context.Context, devicePath string) *SmartHealth {
	if !isATADevice(devicePath) {
		return nil
	}
	// 用同步 OpenFile —— ioctl 没异步语义。ctx 在 ioctl 内部不能强制取消，
	// 但设备 open 本身在卡死时由 RW_NONBLOCK 之外的 timeout 兜底（应用层）。
	f, err := os.OpenFile(devicePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()

	// SMART READ DATA：返回 512 字节属性数据
	buf := make([]byte, 4+512)
	buf[0] = ataCmdSmart
	buf[1] = 1                // sector count
	buf[2] = ataSmartReadData // feature
	buf[3] = 1                // num sectors

	if errno := ioctl(f.Fd(), hdioDriveCmd, unsafe.Pointer(&buf[0])); errno != 0 {
		// ioctl 失败 —— 可能是 USB 桥不透传 / 不是真 ATA / 没权限
		return nil
	}

	h := parseATASmartData(buf[4:])
	if h == nil || !h.Available {
		return nil
	}

	// SMART RETURN STATUS：拿"总体 PASS / FAIL"
	stsBuf := make([]byte, 4+512)
	stsBuf[0] = ataCmdSmart
	stsBuf[1] = 0
	stsBuf[2] = ataSmartReturnSts
	stsBuf[3] = 0
	if errno := ioctl(f.Fd(), hdioDriveCmd, unsafe.Pointer(&stsBuf[0])); errno == 0 {
		// 返回时 stsBuf[4]=lba_low, stsBuf[5]=lba_mid, stsBuf[6]=lba_high
		// 标准答案：lba_mid=0x4F + lba_high=0xC2 → PASS
		//          lba_mid=0xF4 + lba_high=0x2C → FAIL
		if stsBuf[5] == 0xF4 && stsBuf[6] == 0x2C {
			h.Healthy = false
		}
	}

	// 试着拿 model / serial 用 IDENTIFY DEVICE（命令 0xEC，512 字节回包）
	idBuf := make([]byte, 4+512)
	idBuf[0] = 0xEC // IDENTIFY DEVICE
	idBuf[1] = 1
	idBuf[2] = 0
	idBuf[3] = 1
	if errno := ioctl(f.Fd(), hdioDriveCmd, unsafe.Pointer(&idBuf[0])); errno == 0 {
		h.Serial = ataSwapString(idBuf[4+20 : 4+20+20])
		h.Model = ataSwapString(idBuf[4+54 : 4+54+40])
	}

	h.Source = "native"
	return h
}

// ioctl 包一个最朴素的 SYS_IOCTL syscall。
func ioctl(fd uintptr, req uintptr, ptr unsafe.Pointer) syscall.Errno {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(ptr))
	return errno
}

// isATADevice 粗略识别。NVMe / loop / ram 都不走 HDIO_DRIVE_CMD。
func isATADevice(p string) bool {
	base := strings.TrimPrefix(p, "/dev/")
	return strings.HasPrefix(base, "sd") || strings.HasPrefix(base, "hd") || strings.HasPrefix(base, "vd")
}

// ataSwapString IDENTIFY DEVICE 返回的字符串字段是大端 16 位字节交换，
// 还要 trim 末尾的 0x20 (' ') padding。例：'aSsmnug ' → 'Samsung '
func ataSwapString(b []byte) string {
	out := make([]byte, len(b))
	for i := 0; i+1 < len(b); i += 2 {
		out[i] = b[i+1]
		out[i+1] = b[i]
	}
	return strings.TrimSpace(string(out))
}
