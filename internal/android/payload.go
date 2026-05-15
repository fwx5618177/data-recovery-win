package android

// ============================================================================
// .ab payload 解码：解密（如果加密）→ 解压（如果压缩）→ tar 流。
//
// 实现方式：用 io.Reader 链组合，从根本上避免把整个 backup 一次性读入内存。
// 几个 GB 的 backup 在 256MB 工作内存的容器里也能流畅恢复。
//
//   raw payload reader
//      ↓ AES-CBC stream decrypt   (如果加密)
//      ↓ zlib inflate             (如果压缩)
//      ↓ archive/tar 流式枚举
// ============================================================================

import (
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
)

// OpenPayloadReader 把 raw payload byte 流包装成"可读的 tar 流"。
//
// 参数：
//
//	raw     —— 已 Seek 到 PayloadOffset 的 reader
//	header  —— ParseHeader 返回的头部
//	master  —— 仅 header.IsEncrypted() 时需要；非加密传 nil
//
// 返回的 reader 调用方需要 Close（如果是加密+压缩链，Close 会按顺序拆掉）。
func OpenPayloadReader(raw io.Reader, header *ABHeader, master *MasterKey) (io.ReadCloser, error) {
	if header == nil {
		return nil, errors.New("header 不能为 nil")
	}

	current := raw
	var closers []io.Closer

	// 1) 解密层（如果加密）
	if header.IsEncrypted() {
		if master == nil || len(master.Key) != 32 || len(master.IV) != 16 {
			return nil, errors.New("加密 backup 需要传入 master key + IV")
		}
		dec, err := newCBCStreamDecrypter(current, master.Key, master.IV)
		if err != nil {
			return nil, err
		}
		current = dec
		// CBCStreamDecrypter 没有 Close（它只读不持有资源）
	}

	// 2) 解压层（如果压缩）
	if header.IsCompressed {
		zr, err := zlib.NewReader(current)
		if err != nil {
			return nil, fmt.Errorf("zlib 初始化失败（密码可能错？）: %w", err)
		}
		closers = append(closers, zr)
		current = zr
	}

	// 3) 包成 ReadCloser
	return &chainedReadCloser{r: current, closers: closers}, nil
}

// chainedReadCloser 让 OpenPayloadReader 的链式 wrapper 可以一次性 Close
type chainedReadCloser struct {
	r       io.Reader
	closers []io.Closer
}

func (c *chainedReadCloser) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *chainedReadCloser) Close() error {
	var firstErr error
	// 反向 Close（最里面的先关）
	for i := len(c.closers) - 1; i >= 0; i-- {
		if err := c.closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ============================================================================
// AES-CBC 流式解密
//
// 标准库的 cipher.NewCBCDecrypter 接收 *block* 缓冲区（必须是 blocksize 倍数）。
// 我们要把它包装成 io.Reader 让 zlib.Reader / archive/tar 能流式消费。
//
// 还要处理 PKCS7 padding：CBC 解密结束后最后一个 block 可能有 padding。
// 但 .ab 的 payload 整个就是 CBC 加密的 zlib/tar 流，最后一块也是有 padding 的。
// 我们采取的策略：解密时正常输出每一块；当读到 EOF 时，把最后一块的 padding 去掉。
// ============================================================================

type cbcStreamDecrypter struct {
	src       io.Reader
	mode      cipher.BlockMode
	buf       []byte // 已解密但还没返还给调用方的字节
	prevBlock []byte // 已解密但暂未输出（可能是最后一块；要等下一次读到 EOF 才能去 padding）
	doneEOF   bool
}

func newCBCStreamDecrypter(src io.Reader, key, iv []byte) (*cbcStreamDecrypter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key 必须 32B, got %d", len(key))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("AES IV 必须 16B, got %d", len(iv))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cbcStreamDecrypter{
		src:  src,
		mode: cipher.NewCBCDecrypter(block, iv),
	}, nil
}

func (d *cbcStreamDecrypter) Read(p []byte) (int, error) {
	// 已经返完所有数据
	if d.doneEOF && len(d.buf) == 0 {
		return 0, io.EOF
	}

	// 先吐 buf 里残留
	if len(d.buf) > 0 {
		n := copy(p, d.buf)
		d.buf = d.buf[n:]
		if d.doneEOF && len(d.buf) == 0 {
			return n, io.EOF
		}
		return n, nil
	}

	// 从 src 读至少一个 block。
	// 加密文件总长度是 16B 倍数；用 io.ReadFull 整块读。
	chunk := make([]byte, aes.BlockSize*256) // 一次解 4KB
	rn, rerr := io.ReadFull(d.src, chunk)
	if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
		// 流结束或到尾巴 —— rn 必须是 blocksize 倍数（密文如此），否则就是文件损坏
		if rn%aes.BlockSize != 0 {
			return 0, fmt.Errorf("CBC 流尾部对齐错: 剩余 %d 字节", rn)
		}
		if rn > 0 {
			d.mode.CryptBlocks(chunk[:rn], chunk[:rn])
			// 末尾 = prevBlock + 新解的 chunk；最后一块去 padding
			combined := append(d.prevBlock, chunk[:rn]...)
			d.prevBlock = nil
			if len(combined) >= aes.BlockSize {
				out, err := pkcs7Unpad(combined)
				if err != nil {
					return 0, fmt.Errorf("CBC 流尾去 padding 失败: %w", err)
				}
				d.buf = out
			} else {
				d.buf = combined
			}
		} else if len(d.prevBlock) > 0 {
			// 没读到新数据，但 prevBlock 还有；那就是最后一块
			out, err := pkcs7Unpad(d.prevBlock)
			if err != nil {
				return 0, fmt.Errorf("CBC 流尾去 padding 失败: %w", err)
			}
			d.buf = out
			d.prevBlock = nil
		}
		d.doneEOF = true
		// 递归一次输出 buf
		return d.Read(p)
	}
	if rerr != nil {
		return 0, rerr
	}

	// 正常读到完整 chunk，解密。
	d.mode.CryptBlocks(chunk[:rn], chunk[:rn])

	// 把上一轮的 prevBlock 拼到当前块前面，留出 *新的* 最后一块（如果是 EOF 那就是要去 padding 的）。
	combined := append(d.prevBlock, chunk[:rn]...)
	// 保留最后一个 block 给下一轮（可能是文件末尾要去 padding）
	d.prevBlock = combined[len(combined)-aes.BlockSize:]
	d.buf = combined[:len(combined)-aes.BlockSize]

	// 输出
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}
