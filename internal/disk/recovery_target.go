package disk

// ValidateRecoveryTarget 在真实恢复开始前检查输出目录是否安全。
//
// 如果源是磁盘镜像文件（非设备路径），跳过"同盘"检查 ——
// 镜像本身就是源盘的只读副本，把恢复结果写到放镜像的那块盘完全没问题。
// 这是业界 image-first 工作流的关键：镜像一旦 dump 出来，源盘再不被动任何一个字节。
func ValidateRecoveryTarget(sourceDevicePath string, outputDir string) error {
	if !looksLikeDevicePath(sourceDevicePath) {
		return nil
	}
	return validateRecoveryTargetPlatform(sourceDevicePath, outputDir)
}
