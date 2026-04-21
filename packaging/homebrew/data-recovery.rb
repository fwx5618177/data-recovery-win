# Homebrew formula 模板。
#
# 发版时把 VERSION + URL + SHA256 替换成实际值（CI 自动渲染）。
# 用户安装：
#   brew tap your-github-owner/data-recovery
#   brew install data-recovery
#
# 注意：macOS 上读原始磁盘需要 root，brew install 不会自动配 setuid；
# 用户得手动 sudo data-recovery 或用 GUI .app 包（带 osascript 自动 sudo）。

class DataRecovery < Formula
  desc "Open-source cross-platform data recovery (NTFS/APFS/HFS+/BitLocker/RAID)"
  homepage "https://github.com/your-github-owner/data-recovery"
  version "VERSION_PLACEHOLDER"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/your-github-owner/data-recovery/releases/download/v#{version}/DataRecovery-darwin-arm64.tar.gz"
      sha256 "SHA256_DARWIN_ARM64_PLACEHOLDER"
    end
    on_intel do
      url "https://github.com/your-github-owner/data-recovery/releases/download/v#{version}/DataRecovery-darwin-amd64.tar.gz"
      sha256 "SHA256_DARWIN_AMD64_PLACEHOLDER"
    end
  end

  on_linux do
    url "https://github.com/your-github-owner/data-recovery/releases/download/v#{version}/DataRecovery-linux-amd64.tar.gz"
    sha256 "SHA256_LINUX_AMD64_PLACEHOLDER"
  end

  def install
    bin.install "DataRecovery" => "data-recovery"
    # CLI 二进制（可选另发）
    if File.exist?("data-recovery-cli")
      bin.install "data-recovery-cli"
    end
  end

  def caveats
    <<~EOS
      读原始磁盘需要 root 权限。GUI 启动：
        sudo data-recovery
      或用 .app 包（自动弹密码框）。

      CLI：
        sudo data-recovery-cli scan /dev/disk2 --output report.json
    EOS
  end

  test do
    system "#{bin}/data-recovery-cli", "help"
  end
end
