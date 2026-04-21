package backup

import (
	"runtime"
	"strings"
	"testing"
)

func TestGenerateInstallCommand_PerOS(t *testing.T) {
	s := Schedule{
		SourceDir: "/tmp/src",
		DestDir:   "/tmp/dst",
		HourOfDay: 3,
		Frequency: "daily",
	}
	cmd, err := s.GenerateInstallCommand()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	switch runtime.GOOS {
	case "linux", "darwin":
		if !strings.Contains(cmd, "rsync") || !strings.Contains(cmd, "crontab") {
			t.Errorf("Unix cmd 应含 rsync + crontab: %q", cmd)
		}
	case "windows":
		if !strings.Contains(cmd, "schtasks") {
			t.Errorf("Win cmd 应含 schtasks: %q", cmd)
		}
	}
}

func TestGenerateInstallCommand_RejectsEmpty(t *testing.T) {
	if _, err := (Schedule{}).GenerateInstallCommand(); err == nil {
		t.Error("空 source/dest 应报错")
	}
}
