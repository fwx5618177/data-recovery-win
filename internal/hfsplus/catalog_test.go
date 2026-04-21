package hfsplus

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// 合成一个最小 catalog leaf node：1 个 folder record + 1 个 file record。
func TestParseCatalogNode_LeafWithFolderAndFile(t *testing.T) {
	const nodeSize = 4096
	buf := make([]byte, nodeSize)
	// 节点头：kind = -1 (leaf)，存为 byte (0xFF)
	kind := BTNodeKindLeaf
	buf[8] = byte(kind)
	buf[9] = 1                                          // height
	binary.BigEndian.PutUint16(buf[10:12], 2)            // numRecords

	// ---- 第一条：folder "Documents" ----
	folderName := "Documents"
	codes := utf16.Encode([]rune(folderName))
	folderKey := make([]byte, 8+2*len(codes))
	binary.BigEndian.PutUint16(folderKey[0:2], uint16(6+2*len(codes))) // keyLength
	binary.BigEndian.PutUint32(folderKey[2:6], 2)                      // parentID
	binary.BigEndian.PutUint16(folderKey[6:8], uint16(len(codes)))     // nameLen
	for i, c := range codes {
		binary.BigEndian.PutUint16(folderKey[8+i*2:10+i*2], c)
	}
	folderVal := make([]byte, 0x58)
	binary.BigEndian.PutUint16(folderVal[0:2], uint16(CatRecordFolder))
	binary.BigEndian.PutUint32(folderVal[4:8], 42)   // valence
	binary.BigEndian.PutUint32(folderVal[8:12], 100) // folderID
	binary.BigEndian.PutUint32(folderVal[12:16], 1234)
	folderRec := append(folderKey, folderVal...)

	// ---- 第二条：file "kitten.jpg" ----
	fileName := "kitten.jpg"
	fcodes := utf16.Encode([]rune(fileName))
	fileKey := make([]byte, 8+2*len(fcodes))
	binary.BigEndian.PutUint16(fileKey[0:2], uint16(6+2*len(fcodes)))
	binary.BigEndian.PutUint32(fileKey[2:6], 100)
	binary.BigEndian.PutUint16(fileKey[6:8], uint16(len(fcodes)))
	for i, c := range fcodes {
		binary.BigEndian.PutUint16(fileKey[8+i*2:10+i*2], c)
	}
	fileVal := make([]byte, 0xA8)
	binary.BigEndian.PutUint16(fileVal[0:2], uint16(CatRecordFile))
	binary.BigEndian.PutUint32(fileVal[8:12], 200)         // fileID
	binary.BigEndian.PutUint32(fileVal[12:16], 1700000000)
	binary.BigEndian.PutUint64(fileVal[0x58:0x58+8], 12345)        // logicalSize
	binary.BigEndian.PutUint32(fileVal[0x58+12:0x58+16], 3)        // totalBlocks
	// extent[0]: startBlock=10, blockCount=2
	binary.BigEndian.PutUint32(fileVal[0x58+16:0x58+20], 10)
	binary.BigEndian.PutUint32(fileVal[0x58+20:0x58+24], 2)
	// extent[1]: startBlock=20, blockCount=1
	binary.BigEndian.PutUint32(fileVal[0x58+24:0x58+28], 20)
	binary.BigEndian.PutUint32(fileVal[0x58+28:0x58+32], 1)
	fileRec := append(fileKey, fileVal...)

	// 把两条 record 顺序写入 node body（紧接节点头之后从 14 字节开始）
	pos := 14
	folderStart := pos
	copy(buf[pos:], folderRec)
	pos += len(folderRec)
	fileStart := pos
	copy(buf[pos:], fileRec)
	pos += len(fileRec)

	// 节点末尾 offset table（倒着写）：offset[0]=folderStart, offset[1]=fileStart, offset[2]=pos(free start)
	binary.BigEndian.PutUint16(buf[nodeSize-2:nodeSize], uint16(folderStart))
	binary.BigEndian.PutUint16(buf[nodeSize-4:nodeSize-2], uint16(fileStart))
	binary.BigEndian.PutUint16(buf[nodeSize-6:nodeSize-4], uint16(pos))

	n, err := ParseCatalogNode(buf)
	if err != nil {
		t.Fatalf("ParseCatalogNode: %v", err)
	}
	if n.Kind != BTNodeKindLeaf {
		t.Errorf("Kind=%d want leaf=%d", n.Kind, BTNodeKindLeaf)
	}
	if len(n.Records) != 2 {
		t.Fatalf("records=%d want 2", len(n.Records))
	}
	// folder
	if n.Records[0].Folder == nil {
		t.Fatal("第一条应是 folder")
	}
	if n.Records[0].Folder.Name != folderName {
		t.Errorf("folder name=%q want %q", n.Records[0].Folder.Name, folderName)
	}
	if n.Records[0].Folder.FolderID != 100 {
		t.Errorf("folder ID=%d want 100", n.Records[0].Folder.FolderID)
	}
	if n.Records[0].Folder.Valence != 42 {
		t.Errorf("valence=%d want 42", n.Records[0].Folder.Valence)
	}
	// file
	if n.Records[1].File == nil {
		t.Fatal("第二条应是 file")
	}
	if n.Records[1].File.Name != fileName {
		t.Errorf("file name=%q want %q", n.Records[1].File.Name, fileName)
	}
	if n.Records[1].File.LogicalSize != 12345 {
		t.Errorf("logicalSize=%d", n.Records[1].File.LogicalSize)
	}
	if n.Records[1].File.Extents[0].StartBlock != 10 || n.Records[1].File.Extents[0].BlockCount != 2 {
		t.Errorf("extent[0] 错: %+v", n.Records[1].File.Extents[0])
	}
}
