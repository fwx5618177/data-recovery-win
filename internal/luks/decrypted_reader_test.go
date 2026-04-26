package luks

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"

	"data-recovery/internal/testutil"
)

// 端到端 DecryptedReader 测试：
//   1. 构造 plaintext payload
//   2. 用 XTS 按 sector 加密 → underlying 镜像
//   3. 套上 DecryptedReader → 验证 ReadAt 各种 offset/size 都能还原 plaintext

func buildEncryptedPayload(t *testing.T, plaintext []byte, key []byte, payloadOff int64) []byte {
	t.Helper()
	if len(plaintext)%512 != 0 {
		t.Fatalf("plaintext 必须 512 对齐，got %d", len(plaintext))
	}

	// underlying = [前缀填充] || encrypted_payload
	img := make([]byte, payloadOff+int64(len(plaintext)))
	// 前缀放点非零数据，模拟 LUKS header / metadata
	for i := int64(0); i < payloadOff; i++ {
		img[i] = byte(i & 0xFF)
	}

	xtsHelper, err := makeXTSCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(plaintext); off += 512 {
		dst := img[payloadOff+int64(off) : payloadOff+int64(off)+512]
		copy(dst, plaintext[off:off+512])
		xtsHelper.Encrypt(dst, dst, uint64(off/512))
	}
	return img
}

func TestDecryptedReader_FullRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 64)
	plaintext := make([]byte, 8*1024) // 16 sectors
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	const payloadOff = 4096
	img := buildEncryptedPayload(t, plaintext, key, payloadOff)
	underlying := testutil.NewMemReader(img)

	cipher, err := NewSectorCipher("aes", "xts-plain64", key)
	if err != nil {
		t.Fatal(err)
	}
	dr, err := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:  underlying,
		Cipher:      cipher,
		PayloadOff:  payloadOff,
		PayloadSize: int64(len(plaintext)),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 整段读
	got := make([]byte, len(plaintext))
	n, err := dr.ReadAt(got, 0)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != len(plaintext) {
		t.Errorf("读取字节数: got %d, want %d", n, len(plaintext))
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("解密后内容不匹配")
	}
}

func TestDecryptedReader_UnalignedReadStillCorrect(t *testing.T) {
	// 关键测试：调用者随便给 (offset, size)，DecryptedReader 必须按扇区
	// 扩边、解密、再切片，对外像普通 byte stream
	key := bytes.Repeat([]byte{0x99}, 64)
	plaintext := make([]byte, 4096) // 8 sectors
	for i := range plaintext {
		plaintext[i] = byte((i*7 + 3) & 0xFF)
	}

	img := buildEncryptedPayload(t, plaintext, key, 1024)
	underlying := testutil.NewMemReader(img)
	cipher, _ := NewSectorCipher("aes", "xts-plain64", key)
	dr, err := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:  underlying,
		Cipher:      cipher,
		PayloadOff:  1024,
		PayloadSize: int64(len(plaintext)),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		offset int64
		size   int
	}{
		{0, 100},
		{1, 511},
		{511, 2}, // 跨 sector 边界
		{1000, 100},
		{2048, 500}, // 第 4 扇区起
		{4000, 96},  // 末尾
	}
	for _, c := range cases {
		got := make([]byte, c.size)
		n, err := dr.ReadAt(got, c.offset)
		if err != nil {
			t.Errorf("offset=%d size=%d: ReadAt err=%v", c.offset, c.size, err)
			continue
		}
		if n != c.size {
			t.Errorf("offset=%d size=%d: 字节数 got %d want %d", c.offset, c.size, n, c.size)
		}
		if !bytes.Equal(got, plaintext[c.offset:c.offset+int64(c.size)]) {
			t.Errorf("offset=%d size=%d: 内容不匹配", c.offset, c.size)
		}
	}
}

func TestDecryptedReader_EOF(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 64)
	plaintext := make([]byte, 1024) // 2 sectors
	img := buildEncryptedPayload(t, plaintext, key, 0)
	underlying := testutil.NewMemReader(img)
	cipher, _ := NewSectorCipher("aes", "xts-plain64", key)
	dr, _ := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:  underlying,
		Cipher:      cipher,
		PayloadOff:  0,
		PayloadSize: int64(len(plaintext)),
	})

	// 越界返回 EOF
	if _, err := dr.ReadAt(make([]byte, 10), 1024); !errors.Is(err, io.EOF) {
		t.Errorf("越界应 EOF, got %v", err)
	}
	// 跨边界短读 + EOF
	got := make([]byte, 100)
	n, err := dr.ReadAt(got, 950)
	if !errors.Is(err, io.EOF) {
		t.Errorf("跨边界应返回 EOF, got %v", err)
	}
	if n != 74 {
		t.Errorf("短读应只给 74 字节, got %d", n)
	}
	if !bytes.Equal(got[:n], plaintext[950:1024]) {
		t.Errorf("短读内容不匹配")
	}
}

func TestDecryptedReader_RejectsUnalignedPayloadOff(t *testing.T) {
	cipher, _ := NewSectorCipher("aes", "xts-plain64", bytes.Repeat([]byte{0x55}, 64))
	mr := testutil.NewMemReader(make([]byte, 4096))
	if _, err := NewDecryptedReader(DecryptedReaderConfig{
		Underlying: mr, Cipher: cipher, PayloadOff: 100, PayloadSize: 1024,
	}); err == nil {
		t.Errorf("payloadOff 不对齐应被拒绝")
	}
}

// 4K sector 全卷 round-trip：现代 NVMe / Advanced Format 物理盘默认 4096 字节
// 物理扇区，LUKS2 容器在这种盘上会用 sector_size=4096。
func TestDecryptedReader_4KSectorRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 64)
	plaintext := make([]byte, 4*4096) // 4 个 4K sector
	for i := range plaintext {
		plaintext[i] = byte((i*11 + 3) & 0xFF)
	}

	// 用 4K-aware xts 加密构造 underlying
	const payloadOff = 8192
	totalSize := payloadOff + int64(len(plaintext))
	img := make([]byte, totalSize)
	for i := int64(0); i < payloadOff; i++ {
		img[i] = byte(i & 0xFF)
	}
	xtsHelper, err := makeXTSCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(plaintext); off += 4096 {
		dst := img[payloadOff+int64(off) : payloadOff+int64(off)+4096]
		copy(dst, plaintext[off:off+4096])
		// 4K sector：sectorIdx = byte_offset / 4096
		xtsHelper.Encrypt(dst, dst, uint64(off/4096))
	}

	cipher, err := NewSectorCipherWithSize("aes", "xts-plain64", key, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if cipher.SectorSize() != 4096 {
		t.Fatalf("4K cipher.SectorSize() = %d, want 4096", cipher.SectorSize())
	}

	dr, err := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:  testutil.NewMemReader(img),
		Cipher:      cipher,
		PayloadOff:  payloadOff,
		PayloadSize: int64(len(plaintext)),
	})
	if err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(plaintext))
	if _, err := dr.ReadAt(got, 0); err != nil {
		t.Fatalf("4K ReadAt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("4K sector 全卷解密不一致")
	}

	// 非对齐请求也要正确（跨 4K 边界）
	got2 := make([]byte, 100)
	if _, err := dr.ReadAt(got2, 4090); err != nil {
		t.Fatalf("4K 跨边界 ReadAt: %v", err)
	}
	if !bytes.Equal(got2, plaintext[4090:4190]) {
		t.Errorf("4K 跨边界内容不一致")
	}
}

// 缓存命中跳过 cipher：用一个会计数 DecryptSector 的 fakeCipher 验证。
func TestDecryptedReader_CacheSkipsCipherOnHit(t *testing.T) {
	pt := make([]byte, 4*512)
	for i := range pt {
		pt[i] = byte(i)
	}
	// underlying 装"明文" + fakeCipher 不做实际解密只增计数 → ReadAt 拿到的就是 pt
	fc := &countingCipher{}
	mr := testutil.NewMemReader(pt)
	dr, err := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:   mr,
		Cipher:       fc,
		PayloadOff:   0,
		PayloadSize:  int64(len(pt)),
		CacheSectors: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 512)

	// 第 1 次读 sector 0 → cache miss，触发 1 次 Decrypt
	if _, err := dr.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if fc.calls != 1 {
		t.Errorf("第 1 次读应触发 1 次 Decrypt, got %d", fc.calls)
	}

	// 第 2-10 次读同一 sector → cache 全部命中，Decrypt 不再增长
	for i := 0; i < 9; i++ {
		if _, err := dr.ReadAt(got, 0); err != nil {
			t.Fatal(err)
		}
	}
	if fc.calls != 1 {
		t.Errorf("缓存命中后 Decrypt 计数应仍为 1, got %d", fc.calls)
	}

	// 读不同 sector → miss + Decrypt 增长
	if _, err := dr.ReadAt(got, 512); err != nil {
		t.Fatal(err)
	}
	if fc.calls != 2 {
		t.Errorf("新 sector 应触发 1 次新 Decrypt, got %d", fc.calls)
	}
}

// 容量超出后旧 sector 应被淘汰
func TestDecryptedReader_CacheEvicts(t *testing.T) {
	pt := make([]byte, 100*512)
	fc := &countingCipher{}
	mr := testutil.NewMemReader(pt)
	dr, _ := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:   mr,
		Cipher:       fc,
		PayloadOff:   0,
		PayloadSize:  int64(len(pt)),
		CacheSectors: 4, // 只缓存 4 个 sector
	})
	got := make([]byte, 512)

	// 读 sector 0..9 → 每次都 miss + decrypt = 10
	for i := int64(0); i < 10; i++ {
		dr.ReadAt(got, i*512)
	}
	if fc.calls != 10 {
		t.Errorf("初次读 10 个 sector 应有 10 次 Decrypt, got %d", fc.calls)
	}
	// 此时 cache 里是 sector 6..9（最近的 4 个）
	// 重读 sector 0 → 已被淘汰 → 再 decrypt
	dr.ReadAt(got, 0)
	if fc.calls != 11 {
		t.Errorf("被淘汰 sector 重读应再次 Decrypt, got %d", fc.calls)
	}
	// 重读 sector 9 → 仍在 cache → 不增
	dr.ReadAt(got, 9*512)
	if fc.calls != 11 {
		t.Errorf("仍在 cache 的 sector 不应再 Decrypt, got %d", fc.calls)
	}
}

// 多 goroutine 并发 ReadAt 不应 race
func TestDecryptedReader_CacheConcurrent(t *testing.T) {
	pt := make([]byte, 64*512)
	fc := &countingCipher{}
	mr := testutil.NewMemReader(pt)
	dr, _ := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:   mr,
		Cipher:       fc,
		PayloadOff:   0,
		PayloadSize:  int64(len(pt)),
		CacheSectors: 32,
	})

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 512)
			for i := 0; i < 100; i++ {
				dr.ReadAt(buf, int64(i%64)*512)
			}
		}()
	}
	wg.Wait()
	// 验证没 panic / race。具体计数因调度不可预测，不强校验。
}

// countingCipher 是测试专用 SectorCipher：不做实际加解密，只计 DecryptSector 调用次数
type countingCipher struct {
	mu    sync.Mutex
	calls int
}

func (c *countingCipher) DecryptSector(buf []byte, idx uint64) error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	// 不 mutate buf：上层拿到的就是底层"密文"原文
	return nil
}
func (c *countingCipher) SectorSize() int { return 512 }

func TestNewSectorCipherWithSize_RejectsBadSize(t *testing.T) {
	key := make([]byte, 64)
	for _, sz := range []int{0, 256, 1024, 2048, 8192} {
		if _, err := NewSectorCipherWithSize("aes", "xts-plain64", key, sz); err == nil {
			t.Errorf("sector_size=%d 应被拒绝", sz)
		}
	}
}

func TestDecryptedReader_IVBaseOffset(t *testing.T) {
	// LUKS2 segment.iv_tweak 可能不为 0；DecryptedReader 必须把它加到 sector index
	key := bytes.Repeat([]byte{0x22}, 64)
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// 构造时用 sector idx 100, 101 而不是 0, 1
	const ivBase = 100
	xtsHelper, _ := makeXTSCipher(key)
	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	for off := 0; off < len(encrypted); off += 512 {
		xtsHelper.Encrypt(encrypted[off:off+512], encrypted[off:off+512], uint64(off/512+ivBase))
	}

	underlying := testutil.NewMemReader(encrypted)
	cipher, _ := NewSectorCipher("aes", "xts-plain64", key)
	dr, _ := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:  underlying,
		Cipher:      cipher,
		PayloadOff:  0,
		PayloadSize: int64(len(plaintext)),
		IVBase:      ivBase,
	})

	got := make([]byte, len(plaintext))
	if _, err := dr.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("ivBase 偏移没生效")
	}
}
