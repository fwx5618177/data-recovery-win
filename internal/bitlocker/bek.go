package bitlocker

import (
	"fmt"
	"os"
)

// BEKFile 是解析后的 BitLocker startup key 文件。
//
// 文件本身就是一个 FVE metadata block（和卷里的 metadata 同格式），
// 不过里面只含 1 个 EXTERNAL_KEY datum；解出来后 ExternalKey 就是实际用来解 VMK 的 32 字节。
type BEKFile struct {
	GUID        [16]byte // EXTERNAL_KEY datum 的 GUID，用来和卷 VMK 里的 external key 引用匹配
	ExternalKey []byte   // 32 字节实际密钥
	Metadata    *FVEMetadataBlock
}

// ParseBEKFile 读取 .BEK 文件并解出 external key。
//
// .BEK 文件非常小（通常 < 2KB），一次性全读到内存里走 parser。
func ParseBEKFile(path string) (*BEKFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读 BEK 文件失败: %w", err)
	}
	return ParseBEKBytes(data)
}

// ParseBEKBytes 给单元测试用：直接给 BEK 文件字节内容。
func ParseBEKBytes(data []byte) (*BEKFile, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("BEK 数据太短: %d", len(data))
	}
	if string(data[0:8]) != fveOEMID {
		return nil, fmt.Errorf("BEK 签名错: %q", string(data[0:8]))
	}

	// 复用 FVEMetadataBlock parser：它按 memory buffer 或 reader 都能工作。
	// 我们搭一个临时 MemReader 喂给 ParseFVEMetadataBlock。
	reader := &bekMemReader{data: data}
	mb, err := ParseFVEMetadataBlock(reader, 0)
	if err != nil {
		return nil, fmt.Errorf("BEK 结构解析失败: %w", err)
	}

	// 在 datum 树里找 EXTERNAL_KEY
	extDatum := FindDatumByValueType(mb.Datums, DatumValueExternalKey)
	if extDatum == nil {
		return nil, fmt.Errorf("BEK 里没有 EXTERNAL_KEY datum")
	}
	// EXTERNAL_KEY 头部 28 字节：GUID(16) + last_change(8) + reserved(4)，
	// 之后是嵌套的 KEY datum
	if len(extDatum.Body) < 28 {
		return nil, fmt.Errorf("EXTERNAL_KEY datum body 太短: %d", len(extDatum.Body))
	}
	var guid [16]byte
	copy(guid[:], extDatum.Body[0:16])

	keyDatum := FindDatumByValueType(extDatum.Children, DatumValueKey)
	if keyDatum == nil {
		return nil, fmt.Errorf("EXTERNAL_KEY 里没有嵌套 KEY datum")
	}
	if len(keyDatum.Body) < 4+32 {
		return nil, fmt.Errorf("KEY datum body 太短（需要 4+32）: %d", len(keyDatum.Body))
	}
	// body[0:4] = encryption_method（这里是 key 类型标记）；后面是 32 字节 key
	externalKey := make([]byte, 32)
	copy(externalKey, keyDatum.Body[4:4+32])

	return &BEKFile{
		GUID:        guid,
		ExternalKey: externalKey,
		Metadata:    mb,
	}, nil
}

// bekMemReader 只满足 disk.DiskReader 接口最小子集，供 ParseFVEMetadataBlock 用
type bekMemReader struct {
	data []byte
}

func (b *bekMemReader) Open() error  { return nil }
func (b *bekMemReader) Close() error { return nil }
func (b *bekMemReader) ReadAt(buf []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(b.data)) {
		return 0, fmt.Errorf("BEK 读 offset 越界: %d", offset)
	}
	n := copy(buf, b.data[offset:])
	return n, nil
}
func (b *bekMemReader) Size() (int64, error) { return int64(len(b.data)), nil }
func (b *bekMemReader) SectorSize() int      { return 512 }
func (b *bekMemReader) DevicePath() string   { return "bek://mem" }
