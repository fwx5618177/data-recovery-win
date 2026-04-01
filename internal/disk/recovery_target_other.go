//go:build !windows

package disk

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

func validateRecoveryTargetPlatform(sourceDevicePath string, outputDir string) error {
	if strings.TrimSpace(sourceDevicePath) == "" || strings.TrimSpace(outputDir) == "" {
		return nil
	}

	outputDevice, err := mountedDeviceForPath(outputDir)
	if err != nil {
		return fmt.Errorf("无法确认恢复目录所在磁盘: %w", err)
	}

	if outputDevice == "" || !strings.HasPrefix(outputDevice, "/dev/") {
		return nil
	}

	sourceBase := normalizeUnixDiskDevice(sourceDevicePath)
	outputBase := normalizeUnixDiskDevice(outputDevice)
	if sourceBase == "" || outputBase == "" {
		return nil
	}

	if sourceBase == outputBase {
		return fmt.Errorf(
			"恢复目录位于源盘所在的同一块磁盘（源盘 %s，恢复目录 %s），请改选另一块磁盘或外接盘",
			sourceDevicePath,
			filepath.Clean(outputDir),
		)
	}

	return nil
}

func mountedDeviceForPath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	args := [][]string{
		{"-P", cleanPath},
		{cleanPath},
	}

	for _, argList := range args {
		cmd := exec.Command("df", argList...)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		device := parseMountedDevice(string(output))
		if device != "" {
			return device, nil
		}
	}

	return "", fmt.Errorf("df 未返回可识别的挂载设备")
}

func parseMountedDevice(output string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	lineNumber := 0
	lastDevice := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		lineNumber++
		if lineNumber == 1 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		lastDevice = fields[0]
	}

	return lastDevice
}

func normalizeUnixDiskDevice(path string) string {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" {
		return ""
	}

	base := filepath.Base(cleanPath)
	switch {
	case strings.HasPrefix(base, "rdisk"):
		base = "disk" + strings.TrimPrefix(base, "rdisk")
	case strings.HasPrefix(base, "disk"):
		if idx := strings.Index(base[4:], "s"); idx >= 0 {
			base = base[:4+idx]
		}
	case strings.HasPrefix(base, "nvme"), strings.HasPrefix(base, "mmcblk"):
		if idx := strings.LastIndex(base, "p"); idx > 0 && isDigits(base[idx+1:]) {
			base = base[:idx]
		}
	case strings.HasPrefix(base, "sd"), strings.HasPrefix(base, "vd"), strings.HasPrefix(base, "xvd"):
		base = strings.TrimRightFunc(base, func(r rune) bool {
			return unicode.IsDigit(r)
		})
	}

	if base == "" {
		return ""
	}

	return filepath.Join("/dev", base)
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}

	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}

	return true
}
