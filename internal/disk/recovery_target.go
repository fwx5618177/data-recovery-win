package disk

// ValidateRecoveryTarget 在真实恢复开始前检查输出目录是否安全。
func ValidateRecoveryTarget(sourceDevicePath string, outputDir string) error {
	return validateRecoveryTargetPlatform(sourceDevicePath, outputDir)
}
