//go:build windows

package diag

import (
	"syscall"
	"unsafe"
)

// FOLDERID_Desktop 是 Windows Shell 的 KNOWNFOLDERID GUID，
// 引用真实"桌面"路径（包括 OneDrive 重定向 / D: 重定向 / 中文桌面 等情况）。
//
// MSDN reference: https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
//
//	{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
var folderIDDesktop = syscall.GUID{
	Data1: 0xB4BFCC3A,
	Data2: 0xDB2C,
	Data3: 0x424C,
	Data4: [8]byte{0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41},
}

var (
	modShell32               = syscall.NewLazyDLL("shell32.dll")
	procSHGetKnownFolderPath = modShell32.NewProc("SHGetKnownFolderPath")
	modOle32                 = syscall.NewLazyDLL("ole32.dll")
	procCoTaskMemFree        = modOle32.NewProc("CoTaskMemFree")
)

// resolveRealDesktopPath 调 Windows Shell SHGetKnownFolderPath 拿真实桌面路径。
//
// 为什么不能用 os.UserHomeDir() + "\Desktop"：
//   - OneDrive 接管 Desktop 后，真桌面在 %OneDrive%\Desktop
//   - 中文 Windows 用 D:\Documents 重定向 Desktop 时，C:\Users\xxx\Desktop 可能不存在或是空目录
//   - 用户在 "属性 > 位置 > 移动" 改了路径后，硬编码 ~/Desktop 也不对
//
// SHGetKnownFolderPath 是 Windows 唯一权威 API。
//
// 失败时返回空字符串让 caller 回退到其他策略。
//
// v2.8.16 加（用户报"导出诊断包导出到了 C:\Users\xxx\Desktop 但实际桌面在 D:\桌面"）。
func resolveRealDesktopPath() string {
	const (
		// KF_FLAG_DEFAULT = 0
		// KF_FLAG_DONT_VERIFY = 0x00004000  —— 即便目录不存在也返回路径
		flags  = 0
		hToken = 0 // 当前进程 token
	)
	var pathPtr uintptr
	r1, _, _ := procSHGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(&folderIDDesktop)),
		uintptr(flags),
		uintptr(hToken),
		uintptr(unsafe.Pointer(&pathPtr)),
	)
	// S_OK = 0；其它返回值表示失败
	if r1 != 0 || pathPtr == 0 {
		return ""
	}
	// 读 UTF-16 字符串然后释放
	defer procCoTaskMemFree.Call(pathPtr)
	utf16 := (*[1 << 16]uint16)(unsafe.Pointer(pathPtr))
	n := 0
	for n < len(utf16) && utf16[n] != 0 {
		n++
	}
	return syscall.UTF16ToString(utf16[:n])
}
