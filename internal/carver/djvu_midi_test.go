package carver

import (
	"bytes"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// buildDjVu 造最小 DjVu：AT&TFORM + 4B size + "DJVU" + 随机内容填充到 size
func buildDjVu(contentLen int) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString("AT&TFORM")
	// FORM size = contentLen（"DJVU" 起算），big-endian uint32
	binary.Write(buf, binary.BigEndian, uint32(4+contentLen))
	buf.WriteString("DJVU")
	buf.Write(make([]byte, contentLen))
	// IFF 偶字节对齐
	if buf.Len()%2 == 1 {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func TestDetectDjVuSize_Minimal(t *testing.T) {
	data := buildDjVu(100)
	reader := testutil.NewMemReader(append(data, make([]byte, 1024)...))
	size := detectDjVuSize(reader, 0, int64(len(data))+1024)
	if size != int64(len(data)) {
		t.Errorf("DjVu 大小错: got %d want %d", size, len(data))
	}
}

func TestDetectDjVuSize_InvalidSubtypeRejected(t *testing.T) {
	// 正确 AT&TFORM magic 但子类型是 "XXXX"
	buf := &bytes.Buffer{}
	buf.WriteString("AT&TFORM")
	binary.Write(buf, binary.BigEndian, uint32(100))
	buf.WriteString("XXXX")
	buf.Write(make([]byte, 96))

	reader := testutil.NewMemReader(buf.Bytes())
	size := detectDjVuSize(reader, 0, 1024)
	if size != 0 {
		t.Errorf("非 DjVu 子类型应被拒，返回 size=%d", size)
	}
}

// buildMIDI 造最小 MIDI：MThd + 一个 MTrk 块
func buildMIDI(trackLen int) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString("MThd")
	binary.Write(buf, binary.BigEndian, uint32(6))
	buf.Write(make([]byte, 6)) // MThd data: format + ntrks + division
	buf.WriteString("MTrk")
	binary.Write(buf, binary.BigEndian, uint32(trackLen))
	buf.Write(make([]byte, trackLen))
	return buf.Bytes()
}

func TestDetectMIDISize_SingleTrack(t *testing.T) {
	data := buildMIDI(200)
	reader := testutil.NewMemReader(append(data, make([]byte, 1024)...))
	size := detectMIDISize(reader, 0, int64(len(data))+1024)
	if size != int64(len(data)) {
		t.Errorf("MIDI 大小错: got %d want %d", size, len(data))
	}
}

func TestDetectMIDISize_RejectsAbsurdTrackLength(t *testing.T) {
	// MThd + MTrk 里声明 100MB 长度，超过 10MB 上限
	buf := &bytes.Buffer{}
	buf.WriteString("MThd")
	binary.Write(buf, binary.BigEndian, uint32(6))
	buf.Write(make([]byte, 6))
	buf.WriteString("MTrk")
	binary.Write(buf, binary.BigEndian, uint32(100*1024*1024))
	// 不需要填够数据，上限校验在读头部时做

	reader := testutil.NewMemReader(buf.Bytes())
	size := detectMIDISize(reader, 0, 200*1024*1024)
	if size != 0 {
		t.Errorf("异常大小的 track 应被拒，返回 size=%d", size)
	}
}

func TestDetectMIDISize_NoMTrkRejected(t *testing.T) {
	// 只有 MThd 没有 MTrk —— 不是合法 MIDI
	buf := &bytes.Buffer{}
	buf.WriteString("MThd")
	binary.Write(buf, binary.BigEndian, uint32(6))
	buf.Write(make([]byte, 6))

	reader := testutil.NewMemReader(buf.Bytes())
	size := detectMIDISize(reader, 0, 1024)
	if size != 0 {
		t.Errorf("无 MTrk 的 MIDI 应被拒，返回 size=%d", size)
	}
}
