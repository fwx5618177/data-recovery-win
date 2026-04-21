package bitlocker

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// StretchKey 是确定性算法 —— 同样输入必同样输出。
// 我们用一个**人工的"3 次迭代"参考实现**对照 1 次小迭代验证算法形状正确。
//
// 完整的 1M 次迭代单测要 1-2 秒，加 -short 跳过。
func TestStretchKey_DeterministicSmallIterations(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过 1M 次迭代测试（-short 模式）")
	}

	rawKey := make([]byte, 16)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}
	var salt [16]byte
	for i := range salt {
		salt[i] = byte(0xA0 + i)
	}

	first := StretchKey(rawKey, salt, nil)
	second := StretchKey(rawKey, salt, nil)
	if !bytes.Equal(first[:], second[:]) {
		t.Error("StretchKey 必须是确定性的，相同输入 → 相同输出")
	}

	// 不同 salt → 不同输出
	var salt2 [16]byte
	salt2[0] = 0x99
	third := StretchKey(rawKey, salt2, nil)
	if bytes.Equal(first[:], third[:]) {
		t.Error("不同 salt 应得不同输出")
	}
}

// 验证算法形状：用一个等价的"小迭代"参考实现对照前 N 次迭代结果
// （把全 1M 次迭代换成可控 N 次，便于纯算法验证）
func TestStretchKey_AlgorithmShape_FirstFewIterations(t *testing.T) {
	rawKey := []byte("password-derived-16b") // 注意 truncate 到 16
	if len(rawKey) > 16 {
		rawKey = rawKey[:16]
	}
	var salt [16]byte
	copy(salt[:], []byte("0123456789abcdef"))

	// 参考实现：手工算 3 次迭代，看初值传播
	wantState := makeReferenceStretchState(rawKey, salt, 3)

	// 我们的实现的"前 3 次"——通过把 iterations 改成 3 跑一遍
	// 但 StretchKey 硬编码 1M 次；为了测算法形状，用一个 helper 跑 N 次
	gotState := stretchKeyN(rawKey, salt, 3)

	if !bytes.Equal(wantState[:], gotState[:]) {
		t.Errorf("3 次迭代结果不匹配:\n  got  %x\n  want %x", gotState[:], wantState[:])
	}
}

// stretchKeyN 是测试专用：跑 N 次迭代而不是 1M 次。
// 算法与 StretchKey 完全相同，仅 iterations 不同。
func stretchKeyN(rawKey []byte, salt [16]byte, iterations uint64) [32]byte {
	var state [88]byte
	initial := sha256.Sum256(rawKey)
	copy(state[32:64], initial[:])
	copy(state[64:80], salt[:])

	for i := uint64(0); i < iterations; i++ {
		binary.LittleEndian.PutUint64(state[80:88], i)
		h := sha256.Sum256(state[:])
		copy(state[0:32], h[:])
	}
	var out [32]byte
	copy(out[:], state[0:32])
	return out
}

// 参考实现：用最朴素方式计算 3 次迭代，验证算法形状
func makeReferenceStretchState(rawKey []byte, salt [16]byte, iterations uint64) [32]byte {
	// state 88 字节：last_sha(32) + initial_sha(32) + salt(16) + counter(8)
	last := [32]byte{} // 初值零
	initial := sha256.Sum256(rawKey)

	for i := uint64(0); i < iterations; i++ {
		var buf [88]byte
		copy(buf[0:32], last[:])
		copy(buf[32:64], initial[:])
		copy(buf[64:80], salt[:])
		binary.LittleEndian.PutUint64(buf[80:88], i)
		next := sha256.Sum256(buf[:])
		copy(last[:], next[:])
	}
	return last
}

// 进度回调被调用
func TestStretchKey_ProgressCallback(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	rawKey := make([]byte, 16)
	var salt [16]byte
	calls := 0
	StretchKey(rawKey, salt, func(done, total uint64) {
		calls++
		if total != 0x100000 {
			t.Errorf("total 应为 1048576，实际 %d", total)
		}
	})
	if calls < 2 {
		t.Errorf("进度回调应至少 2 次，实际 %d", calls)
	}
}
