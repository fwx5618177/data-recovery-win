package veracrypt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 7801 Appendix A.1 Test Vector
//
//	Key:        8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
//	Plaintext:  1122334455667700ffeeddccbbaa9988
//	Ciphertext: 7f679d90bebc24305a468d42b9d4edcd
func TestKuznyechik_RFC7801_Encrypt(t *testing.T) {
	key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt, _ := hex.DecodeString("1122334455667700ffeeddccbbaa9988")
	wantCT, _ := hex.DecodeString("7f679d90bebc24305a468d42b9d4edcd")

	c, err := NewKuznyechikCipher(key)
	if err != nil {
		t.Fatalf("NewKuznyechikCipher: %v", err)
	}
	ct := make([]byte, 16)
	c.Encrypt(ct, pt)
	if !bytes.Equal(ct, wantCT) {
		t.Errorf("Encrypt: got %x want %x", ct, wantCT)
	}
}

// RFC 7801 reverse: Decrypt(Encrypt(P)) == P
func TestKuznyechik_RFC7801_Decrypt(t *testing.T) {
	key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	wantPT, _ := hex.DecodeString("1122334455667700ffeeddccbbaa9988")
	ct, _ := hex.DecodeString("7f679d90bebc24305a468d42b9d4edcd")

	c, err := NewKuznyechikCipher(key)
	if err != nil {
		t.Fatalf("NewKuznyechikCipher: %v", err)
	}
	pt := make([]byte, 16)
	c.Decrypt(pt, ct)
	if !bytes.Equal(pt, wantPT) {
		t.Errorf("Decrypt: got %x want %x", pt, wantPT)
	}
}

// Round-trip 多种 key/plaintext
func TestKuznyechik_RoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		keyHex string
		ptHex  string
	}{
		{"all-zero", "0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000"},
		{"all-FF", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff"},
		{"alternating", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "5555555555555555555555555555555555555555555555555555555555555555"[:32]},
		{"pattern", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "00112233445566778899aabbccddeeff"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, _ := hex.DecodeString(c.keyHex)
			pt, _ := hex.DecodeString(c.ptHex)
			cipher, err := NewKuznyechikCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			ct := make([]byte, 16)
			cipher.Encrypt(ct, pt)
			rec := make([]byte, 16)
			cipher.Decrypt(rec, ct)
			if !bytes.Equal(rec, pt) {
				t.Errorf("round-trip fail: pt=%x ct=%x rec=%x", pt, ct, rec)
			}
			if bytes.Equal(ct, pt) {
				t.Error("ciphertext == plaintext (cipher 无效)")
			}
		})
	}
}

// 验证 piTable 是双射（必要条件，否则 SBOX 不可逆）
func TestKuznyechik_PiTableIsBijection(t *testing.T) {
	seen := [256]bool{}
	for _, v := range piTable {
		if seen[v] {
			t.Fatalf("piTable 不是双射，重复值 %d", v)
		}
		seen[v] = true
	}
	// piInvTable 是 piTable 的逆
	for i := 0; i < 256; i++ {
		if piInvTable[piTable[i]] != uint8(i) {
			t.Errorf("piInvTable[piTable[%d]] != %d", i, i)
		}
	}
}

// XTS round-trip：encrypt 然后 decrypt 还原
func TestKuznyechikXTS_RoundTrip(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	kx, err := newKuznyechikXTSCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// 构造一个 512B 明文 sector
	plaintext := make([]byte, 512)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	encrypted := append([]byte(nil), plaintext...)

	// 我们没有 EncryptSector 接口（VC 解密器只读 disk），所以
	// 用 cipher Encrypt 路径模拟 + 然后 DecryptSector 验证
	encryptXTS(t, kx, encrypted, 42)

	// 验证不等于原文
	if bytes.Equal(encrypted, plaintext) {
		t.Error("encrypt 没改变 buf")
	}

	// DecryptSector 还原
	if err := kx.DecryptSector(encrypted, 42); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encrypted, plaintext) {
		t.Errorf("XTS round-trip 不一致")
	}
}

// 测试用 helper：调用 cipher Encrypt + tweak 模拟 XTS encrypt
func encryptXTS(t *testing.T, kx *kuznyechikXTSCipher, buf []byte, sectorIdx uint64) {
	t.Helper()
	if len(buf) != 512 {
		t.Fatal("buf 必须 512")
	}
	var tweak [16]uint8
	tweak[0] = byte(sectorIdx)
	tweak[1] = byte(sectorIdx >> 8)
	tweak[2] = byte(sectorIdx >> 16)
	tweak[3] = byte(sectorIdx >> 24)
	tweak[4] = byte(sectorIdx >> 32)
	tweak[5] = byte(sectorIdx >> 40)
	tweak[6] = byte(sectorIdx >> 48)
	tweak[7] = byte(sectorIdx >> 56)
	kx.tweakKey.Encrypt(tweak[:], tweak[:])

	for i := 0; i < 32; i++ {
		off := i * 16
		var block [16]uint8
		for j := 0; j < 16; j++ {
			block[j] = buf[off+j] ^ tweak[j]
		}
		kx.dataKey.Encrypt(block[:], block[:])
		for j := 0; j < 16; j++ {
			buf[off+j] = block[j] ^ tweak[j]
		}
		gf128Mul2(tweak[:])
	}
}
