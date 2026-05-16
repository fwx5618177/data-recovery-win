//go:build windows

package disk

import (
	"encoding/binary"
	"testing"
)

// TestBuildNVMeGetLogPageBuffer_Layout 锁住 STORAGE_PROTOCOL_COMMAND + NVMe
// Admin Submission Queue Entry 的字节布局，避免后人改字段偏移导致 NVMe SMART
// 失败 / 数据缓冲区错位 / DataFromDeviceBufferOffset 指错地方。
//
// 字段偏移参考 Microsoft Storage Protocol Specific Commands API + NVM Express 1.4。
func TestBuildNVMeGetLogPageBuffer_Layout(t *testing.T) {
	buf := buildNVMeGetLogPageBuffer(nvmeLIDSmartHealth, nvmeNSIDBroadcast)

	expectedTotal := nvmeStorageProtoHeaderSize + nvmeAdminCmdSize + nvmeLogSmartSize
	if len(buf) != expectedTotal {
		t.Fatalf("buf 长度: 期望 %d, 得到 %d", expectedTotal, len(buf))
	}

	// ---- STORAGE_PROTOCOL_COMMAND header 字段 ----
	checkU32 := func(off int, want uint32, name string) {
		t.Helper()
		got := binary.LittleEndian.Uint32(buf[off : off+4])
		if got != want {
			t.Errorf("%s @ offset %d: 期望 0x%08X, 得到 0x%08X", name, off, want, got)
		}
	}
	checkU32(0, storageProtocolVersion1, "Version")
	checkU32(4, nvmeStorageProtoHeaderSize, "Length (header only = 80B)")
	checkU32(8, storageProtocolTypeNvme, "ProtocolType = ProtocolTypeNvme(3)")
	checkU32(24, nvmeAdminCmdSize, "CommandLength = 64")
	checkU32(36, nvmeLogSmartSize, "DataFromDeviceTransferLength = 512")
	checkU32(40, 10, "TimeOutValue = 10s")
	checkU32(52, nvmeStorageProtoHeaderSize+nvmeAdminCmdSize, "DataFromDeviceBufferOffset = 144")
	checkU32(56, storageProtoSpecNvmeAdm, "CommandSpecific = AdminCommand(1)")

	// ---- NVMe Admin Submission Queue Entry at offset 80 ----
	cmdOff := nvmeStorageProtoHeaderSize
	if buf[cmdOff+0] != nvmeOpcodeGetLogPage {
		t.Errorf("OPC @ cmd offset 0: 期望 0x%02X (Get Log Page), 得到 0x%02X",
			nvmeOpcodeGetLogPage, buf[cmdOff+0])
	}
	if buf[cmdOff+1] != 0 {
		t.Errorf("FUSE/PSDT @ cmd offset 1: 期望 0, 得到 0x%02X", buf[cmdOff+1])
	}
	gotNSID := binary.LittleEndian.Uint32(buf[cmdOff+4 : cmdOff+8])
	if gotNSID != nvmeNSIDBroadcast {
		t.Errorf("NSID @ cmd offset 4: 期望 0x%08X (broadcast), 得到 0x%08X",
			nvmeNSIDBroadcast, gotNSID)
	}

	// CDW10: bits 31:16 = NUMDL(127), bits 7:0 = LID(0x02)
	gotCDW10 := binary.LittleEndian.Uint32(buf[cmdOff+40 : cmdOff+44])
	wantCDW10 := uint32(127)<<16 | uint32(nvmeLIDSmartHealth)
	if gotCDW10 != wantCDW10 {
		t.Errorf("CDW10 @ cmd offset 40: 期望 0x%08X (NUMDL=127|LID=2), 得到 0x%08X",
			wantCDW10, gotCDW10)
	}

	// CDW11..15 必须全 0
	for i := 44; i < 64; i += 4 {
		if v := binary.LittleEndian.Uint32(buf[cmdOff+i : cmdOff+i+4]); v != 0 {
			t.Errorf("CDW%d @ cmd offset %d 应为 0, 得到 0x%08X", (i-40)/4+10, i, v)
		}
	}

	// 数据缓冲区起点必须留空（驱动会写入）
	dataOff := nvmeStorageProtoHeaderSize + nvmeAdminCmdSize
	for i := dataOff; i < dataOff+16; i++ {
		if buf[i] != 0 {
			t.Errorf("data buf @ offset %d 初始应为 0, 得到 0x%02X", i, buf[i])
		}
	}
}
