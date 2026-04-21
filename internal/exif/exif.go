// Package exif 实现"已恢复图片按 EXIF 拍摄日期归档"。
//
// 用户场景：扫出 5 万张照片，全是 file001.jpg / file002.jpg；想按"2023-08 巴厘岛旅行"
// 这种时间段分子目录看更友好。
//
// 我们读 JPEG 里的 EXIF DateTimeOriginal (tag 0x9003) 或 DateTime (tag 0x0132)，
// 解出拍摄日期 → 让上层把文件归到 yyyy/mm/ 子目录。
//
// 不依赖 image/jpeg：只解 APP1 segment 里的 TIFF/EXIF 子结构，规模 ~150 行。
//
// HEIC / HEIF 也用 EXIF 但藏在 ISO BMFF box 里 — 当前不支持，留 TODO。
package exif

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// ExtractDateTime 从 JPEG 字节流头部抽取拍摄时间。
//
// 解析路径：
//   1. JPEG SOI (0xFFD8)
//   2. 跳过到 APP1 marker (0xFFE1)
//   3. APP1 payload 头是 "Exif\0\0"
//   4. 之后是 TIFF header："II"或"MM"+ 0x002A + 4 字节 IFD0 偏移
//   5. IFD0 entries 找 DateTime (0x0132)
//   6. 顺着 IFD0 的 ExifIFD pointer (0x8769) 找 DateTimeOriginal (0x9003) — 优先用这个
//
// 时间字符串格式 "YYYY:MM:DD HH:MM:SS"。
//
// 失败返回 zero time + nil error（不是错；很多 JPEG 没 EXIF）。
func ExtractDateTime(jpeg []byte) (time.Time, error) {
	if len(jpeg) < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8 {
		return time.Time{}, fmt.Errorf("非 JPEG: missing SOI")
	}

	pos := 2
	for pos+4 < len(jpeg) {
		if jpeg[pos] != 0xFF {
			pos++
			continue
		}
		marker := jpeg[pos+1]
		if marker == 0x00 || marker == 0xFF {
			pos++
			continue
		}
		// SOS / EOI = 进入数据区，APP 段不会再有
		if marker == 0xDA || marker == 0xD9 {
			return time.Time{}, nil
		}
		segLen := int(binary.BigEndian.Uint16(jpeg[pos+2 : pos+4]))
		if segLen < 2 || pos+2+segLen > len(jpeg) {
			return time.Time{}, nil
		}
		if marker == 0xE1 { // APP1
			payload := jpeg[pos+4 : pos+2+segLen]
			if t, ok := parseEXIFPayload(payload); ok {
				return t, nil
			}
		}
		pos += 2 + segLen
	}
	return time.Time{}, nil
}

// parseEXIFPayload "Exif\0\0" + TIFF header + IFD0 → DateTime / DateTimeOriginal
func parseEXIFPayload(p []byte) (time.Time, bool) {
	if len(p) < 8 || !bytes.HasPrefix(p, []byte("Exif\x00\x00")) {
		return time.Time{}, false
	}
	tiff := p[6:]
	if len(tiff) < 8 {
		return time.Time{}, false
	}
	var bo binary.ByteOrder
	switch string(tiff[0:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return time.Time{}, false
	}
	if bo.Uint16(tiff[2:4]) != 0x002A {
		return time.Time{}, false
	}
	ifd0Off := int(bo.Uint32(tiff[4:8]))
	if ifd0Off >= len(tiff) {
		return time.Time{}, false
	}

	// IFD0：先找 DateTime (0x0132) + ExifIFD pointer (0x8769)
	dt, exifIFDOff := scanIFD(tiff, ifd0Off, bo)

	// 如果 IFD0 有 ExifIFD 指针，优先看 DateTimeOriginal (0x9003)
	if exifIFDOff > 0 && exifIFDOff < len(tiff) {
		if dto, _ := scanIFDForDateTimeOriginal(tiff, exifIFDOff, bo); !dto.IsZero() {
			return dto, true
		}
	}
	if !dt.IsZero() {
		return dt, true
	}
	return time.Time{}, false
}

// scanIFD 解一个 IFD：返回 (DateTime, ExifIFDPointerOffset)
func scanIFD(tiff []byte, ifdOff int, bo binary.ByteOrder) (time.Time, int) {
	if ifdOff+2 > len(tiff) {
		return time.Time{}, 0
	}
	n := int(bo.Uint16(tiff[ifdOff : ifdOff+2]))
	if 2+n*12 > len(tiff)-ifdOff {
		return time.Time{}, 0
	}
	var dt time.Time
	var exifPtr int
	for i := 0; i < n; i++ {
		ent := tiff[ifdOff+2+i*12 : ifdOff+2+(i+1)*12]
		tag := bo.Uint16(ent[0:2])
		typ := bo.Uint16(ent[2:4])
		count := int(bo.Uint32(ent[4:8]))
		valueOrOffset := bo.Uint32(ent[8:12])
		switch tag {
		case 0x0132: // DateTime
			if typ == 2 && count >= 19 { // ASCII string，"YYYY:MM:DD HH:MM:SS\0" = 20 字节
				if int(valueOrOffset)+19 <= len(tiff) {
					dt = parseEXIFTime(string(tiff[valueOrOffset : valueOrOffset+19]))
				}
			}
		case 0x8769: // ExifIFDPointer
			if typ == 4 && count == 1 {
				exifPtr = int(valueOrOffset)
			}
		}
	}
	return dt, exifPtr
}

// scanIFDForDateTimeOriginal 在 ExifIFD 里找 DateTimeOriginal (0x9003)
func scanIFDForDateTimeOriginal(tiff []byte, ifdOff int, bo binary.ByteOrder) (time.Time, error) {
	if ifdOff+2 > len(tiff) {
		return time.Time{}, fmt.Errorf("exif ifd 越界")
	}
	n := int(bo.Uint16(tiff[ifdOff : ifdOff+2]))
	if 2+n*12 > len(tiff)-ifdOff {
		return time.Time{}, fmt.Errorf("exif ifd 长度异常")
	}
	for i := 0; i < n; i++ {
		ent := tiff[ifdOff+2+i*12 : ifdOff+2+(i+1)*12]
		tag := bo.Uint16(ent[0:2])
		typ := bo.Uint16(ent[2:4])
		count := int(bo.Uint32(ent[4:8]))
		valueOrOffset := bo.Uint32(ent[8:12])
		if tag == 0x9003 && typ == 2 && count >= 19 {
			if int(valueOrOffset)+19 <= len(tiff) {
				return parseEXIFTime(string(tiff[valueOrOffset : valueOrOffset+19])), nil
			}
		}
	}
	return time.Time{}, nil
}

// ExtractDateTimeOrZero 按 ext 选 JPEG / HEIC parser；失败一律返回 zero time（不报错）。
func ExtractDateTimeOrZero(data []byte, ext string) time.Time {
	switch ext {
	case "jpg", "jpeg":
		t, _ := ExtractDateTime(data)
		return t
	case "heic", "heif":
		t, _ := ExtractDateTimeHEIC(data)
		return t
	}
	return time.Time{}
}

// parseEXIFTime "2023:08:15 14:30:00" → time.Time（local）
func parseEXIFTime(s string) time.Time {
	t, err := time.ParseInLocation("2006:01:02 15:04:05", s, time.Local)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ArchiveSubdir 把拍摄时间转成"YYYY/MM/" 子目录字符串。
// 失败（time 为零）返回 "Unknown_Date" 让上层有兜底。
func ArchiveSubdir(t time.Time) string {
	if t.IsZero() {
		return "Unknown_Date"
	}
	return fmt.Sprintf("%04d/%02d", t.Year(), int(t.Month()))
}

// ExtractDateTimeHEIC HEIC/HEIF EXIF 在 ISO BMFF 容器里：meta box → iinf
// → iloc 找到 "Exif" item 的字节范围。完整 BMFF 解析复杂，我们做精简版：
//
//	1. 顺着 box 链找 meta box
//	2. 在 meta 里搜"Exif" 的字面 magic
//	3. 在它附近找 TIFF II/MM 头并 parseEXIFPayload
//
// 不严格按规范但对 iPhone / 现代相机出的标准 HEIC 都 work。
func ExtractDateTimeHEIC(heic []byte) (time.Time, error) {
	if len(heic) < 12 {
		return time.Time{}, fmt.Errorf("HEIC 太短")
	}
	// 第一个 box 应是 ftyp
	if string(heic[4:8]) != "ftyp" {
		return time.Time{}, fmt.Errorf("非 BMFF: 缺 ftyp")
	}
	brand := string(heic[8:12])
	if brand != "heic" && brand != "heix" && brand != "mif1" && brand != "msf1" && brand != "hevc" {
		return time.Time{}, fmt.Errorf("非 HEIC brand: %q", brand)
	}
	// 启发式：在前 256KB 里找 "Exif\0\0" 模式（实际 HEIC EXIF 在 mdat 里，紧跟着这个 prefix）
	scanLen := len(heic)
	if scanLen > 256*1024 {
		scanLen = 256 * 1024
	}
	idx := bytesIndex(heic[:scanLen], []byte("Exif\x00\x00"))
	if idx < 0 {
		return time.Time{}, nil // 没 EXIF
	}
	payload := heic[idx:]
	if t, ok := parseEXIFPayload(payload); ok {
		return t, nil
	}
	return time.Time{}, nil
}

func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// LivePhotoPair 描述一对 iPhone Live Photo：HEIC 静态图 + 同名 MOV 视频。
// iPhone 拍 Live Photo 时：IMG_1234.HEIC + IMG_1234.MOV，basename 相同 + 扩展名差异。
type LivePhotoPair struct {
	HEICName string
	MOVName  string
	BaseName string // 不含扩展的公共名
}

// FindLivePhotoPairs 从一组文件名里找出可能的 Live Photo 配对。
// 完整匹配还应核对 EXIF 时间戳一致 / MOV duration < 5s 等；本工具按"同名"启发即可。
func FindLivePhotoPairs(filenames []string) []LivePhotoPair {
	heics := make(map[string]string) // base → fullname
	movs := make(map[string]string)
	for _, n := range filenames {
		base, ext := splitExt(n)
		switch lower(ext) {
		case ".heic", ".heif":
			heics[base] = n
		case ".mov":
			movs[base] = n
		}
	}
	var pairs []LivePhotoPair
	for base, h := range heics {
		if m, ok := movs[base]; ok {
			pairs = append(pairs, LivePhotoPair{HEICName: h, MOVName: m, BaseName: base})
		}
	}
	return pairs
}

func splitExt(name string) (base, ext string) {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[:i], name[i:]
		}
		if name[i] == '/' || name[i] == '\\' {
			break
		}
	}
	return name, ""
}

func lower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
