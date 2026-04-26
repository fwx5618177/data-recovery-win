package luks

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"data-recovery/internal/testutil"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// 端到端 OpenAndUnlock：构造完整的 LUKS2 卷镜像（header + JSON + keyslot + payload），
// 用 OpenAndUnlock 拿到 DecryptedReader，验证 ReadAt(0) 返回的是预先埋的"模拟 NTFS 引导扇区"
// 标记。这是从用户视角的最终回归测试 —— 任何环节错位都会让解密内容不匹配。

func buildLUKS2VolumeImage(t *testing.T, password string, masterKey []byte, plaintextPayload []byte) []byte {
	t.Helper()
	if len(plaintextPayload)%512 != 0 {
		t.Fatalf("plaintextPayload 必须 512 对齐, got %d", len(plaintextPayload))
	}
	const (
		stripes      = 128
		mkLen        = 64
		argonT       = 1
		argonM       = 4096
		argonP       = 1
		digestIter   = 1000
		ksOffset     = 32 * 1024
		ksSize       = 64 * 1024
		payloadStart = 1 * 1024 * 1024 // 1MB 起 → 给 header/keyslots 留足空间
	)

	totalSize := payloadStart + len(plaintextPayload)
	img := make([]byte, totalSize)

	// ---- binary header ----
	copy(img[0:6], luksMagic)
	binary.BigEndian.PutUint16(img[6:8], 2)
	binary.BigEndian.PutUint64(img[8:16], 16384)
	binary.BigEndian.PutUint64(img[16:24], 1)
	copy(img[24:72], "ds-test-luks2")
	copy(img[72:104], "sha256")
	for i := 0; i < 64; i++ {
		img[104+i] = byte(i ^ 0xA5)
	}
	copy(img[168:208], "11112222-3333-4444-5555-666677778888")
	copy(img[208:256], "")

	// ---- argon2id 派生 keyslot key ----
	kdfSalt := bytes.Repeat([]byte{0xAB}, 32)
	keyslotKey := argon2.IDKey([]byte(password), kdfSalt, argonT, argonM, argonP, mkLen)

	// ---- AFsplit master key ----
	rand := make([]byte, mkLen*(stripes-1))
	for i := range rand {
		rand[i] = byte(i*7 + 5)
	}
	afSplit, err := AFsplit(masterKey, stripes, rand, sha256.New)
	if err != nil {
		t.Fatal(err)
	}
	stripeBytes := mkLen * stripes // 8192 = 16 sectors

	// 加密 afSplit
	encryptedKS := make([]byte, stripeBytes)
	copy(encryptedKS, afSplit)
	xtsHelper, err := makeXTSCipher(keyslotKey)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < stripeBytes; off += 512 {
		xtsHelper.Encrypt(encryptedKS[off:off+512], encryptedKS[off:off+512], uint64(off/512))
	}
	copy(img[ksOffset:ksOffset+stripeBytes], encryptedKS)

	// ---- payload：用 master_key 加密 ----
	payloadXTS, err := makeXTSCipher(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(plaintextPayload); off += 512 {
		dst := img[payloadStart+off : payloadStart+off+512]
		copy(dst, plaintextPayload[off:off+512])
		// LUKS2 默认 iv_tweak=0；sector index 从 payload 起算
		payloadXTS.Encrypt(dst, dst, uint64(off/512))
	}

	// ---- master key digest ----
	digestSalt := bytes.Repeat([]byte{0xCD}, 32)
	mkDigest := pbkdf2.Key(masterKey, digestSalt, digestIter, 32, sha256.New)

	// ---- JSON metadata ----
	meta := LUKS2Metadata{
		Keyslots: map[string]*LUKS2Keyslot{
			"0": {
				Type:    "luks2",
				KeySize: mkLen,
				KDF: LUKS2KDF{
					Type:   "argon2id",
					Salt:   base64.StdEncoding.EncodeToString(kdfSalt),
					Time:   argonT,
					Memory: argonM,
					CPUs:   argonP,
				},
				AF: LUKS2AF{Type: "luks1", Stripes: stripes, Hash: "sha256"},
				Area: LUKS2Area{
					Type:       "raw",
					Offset:     fmt.Sprintf("%d", ksOffset),
					Size:       fmt.Sprintf("%d", ksSize),
					Encryption: "aes-xts-plain64",
					KeySize:    mkLen,
				},
			},
		},
		Segments: map[string]*LUKS2Segment{
			"0": {
				Type:       "crypt",
				Offset:     fmt.Sprintf("%d", payloadStart),
				Size:       fmt.Sprintf("%d", len(plaintextPayload)),
				IVTweak:    "0",
				Encryption: "aes-xts-plain64",
				SectorSize: 512,
			},
		},
		Digests: map[string]*LUKS2Digest{
			"0": {
				Type:       "pbkdf2",
				Keyslots:   []string{"0"},
				Segments:   []string{"0"},
				Salt:       base64.StdEncoding.EncodeToString(digestSalt),
				Digest:     base64.StdEncoding.EncodeToString(mkDigest),
				Iterations: digestIter,
				Hash:       "sha256",
			},
		},
		Config: &LUKS2Config{
			JSONSize:     "12288",
			KeyslotsSize: fmt.Sprintf("%d", ksSize),
		},
	}
	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	copy(img[4096:], jsonBytes)

	// csum
	tmp := make([]byte, 4096)
	copy(tmp, img[:4096])
	for i := 448; i < 448+64; i++ {
		tmp[i] = 0
	}
	h := sha256.New()
	h.Write(tmp)
	h.Write(img[4096:16384])
	csum := h.Sum(nil)
	copy(img[448:448+32], csum)

	return img
}

func TestOpenAndUnlock_LUKS2_FullVolume(t *testing.T) {
	const password = "TestVolumePassword2026"
	masterKey := bytes.Repeat([]byte{0x55}, 64)

	// 模拟 payload：在第一个扇区前几字节埋个 NTFS-like 标记，后面跟可识别图案
	plaintext := make([]byte, 8*1024)
	copy(plaintext[:8], "NTFSPLOT")
	for i := 8; i < len(plaintext); i++ {
		plaintext[i] = byte((i * 13) & 0xFF)
	}

	img := buildLUKS2VolumeImage(t, password, masterKey, plaintext)
	underlying := testutil.NewMemReader(img)

	uv, err := OpenAndUnlock(underlying, 0, password)
	if err != nil {
		t.Fatalf("OpenAndUnlock: %v", err)
	}
	defer uv.Close()

	if uv.Version != 2 {
		t.Errorf("应识别为 LUKS2, got version=%d", uv.Version)
	}
	if uv.SlotID != "0" {
		t.Errorf("应在 keyslot 0 命中, got %s", uv.SlotID)
	}
	if uv.Cipher != "aes-xts-plain64" {
		t.Errorf("cipher 不对: %s", uv.Cipher)
	}

	// 整段读 + 比对
	got := make([]byte, len(plaintext))
	n, err := uv.Reader.ReadAt(got, 0)
	if err != nil {
		t.Fatalf("解密 reader ReadAt: %v", err)
	}
	if n != len(plaintext) {
		t.Errorf("读取字节数 %d != %d", n, len(plaintext))
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("解密 payload 与原文不一致")
	}
	if !bytes.Equal(got[:8], []byte("NTFSPLOT")) {
		t.Errorf("payload 头部标记丢失")
	}

	// Close 后 master key 应清零
	mkCopy := append([]byte{}, uv.MasterKey...)
	uv.Close()
	if uv.MasterKey != nil && bytes.Equal(uv.MasterKey, mkCopy) {
		t.Errorf("Close 后 master key 未清零")
	}
}

func TestOpenAndUnlock_RejectsNonLUKS(t *testing.T) {
	img := make([]byte, 1024*1024)
	for i := range img {
		img[i] = byte(i)
	}
	underlying := testutil.NewMemReader(img)
	if _, err := OpenAndUnlock(underlying, 0, "anything"); err == nil {
		t.Errorf("非 LUKS 应被拒绝")
	}
}

func TestOpenAndUnlock_WrongPassword(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x77}, 64)
	plaintext := make([]byte, 1024)
	img := buildLUKS2VolumeImage(t, "right", masterKey, plaintext)
	underlying := testutil.NewMemReader(img)

	if _, err := OpenAndUnlock(underlying, 0, "wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("错密码应返回 ErrWrongPassword, got %v", err)
	}
}

// 进度回调验证：成功 unlock 应至少触发 header_read / trying_keyslot / ready 三个 stage
func TestOpenAndUnlockWithProgress_StagesEmitted(t *testing.T) {
	const password = "ProgressCBTest"
	masterKey := bytes.Repeat([]byte{0x66}, 64)
	plaintext := make([]byte, 1024)
	img := buildLUKS2VolumeImage(t, password, masterKey, plaintext)
	underlying := testutil.NewMemReader(img)

	stages := map[string]int{}
	progress := func(stage string, tried, total int, info string) {
		stages[stage]++
	}

	uv, err := OpenAndUnlockWithProgress(underlying, 0, password, progress)
	if err != nil {
		t.Fatalf("OpenAndUnlockWithProgress: %v", err)
	}
	defer uv.Close()

	for _, want := range []string{"header_read", "trying_keyslot", "ready"} {
		if stages[want] == 0 {
			t.Errorf("缺少 stage 回调: %q (实际 stages: %v)", want, stages)
		}
	}
}
