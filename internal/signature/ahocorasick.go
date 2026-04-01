// Package signature 提供文件签名识别与多模式匹配功能。
//
// 本文件实现 Aho-Corasick 多模式匹配算法——业界公认的多模式字符串搜索最优算法。
//
// 时间复杂度: O(n + m + z)
//   - n: 待搜索文本长度
//   - m: 所有模式的总长度
//   - z: 匹配总数
//
// 相比逐个模式搜索的 O(n*k)，本算法快 k 倍（k 为模式数量）。
// 对于文件签名扫描场景（27+ 种文件类型、40+ 个 header 变体），
// 只需一次线性扫描即可同时匹配所有签名模式。
package signature

import (
	"data-recovery/internal/types"
)

// Match 表示一次签名匹配结果
type Match struct {
	Offset    int64                // 匹配位置在原始数据中的绝对字节偏移
	Signature *types.FileSignature // 匹配到的文件签名定义
	Pattern   []byte               // 匹配到的具体 header 魔术字节模式
}

// acNode 是 Aho-Corasick 自动机的节点
//
// 自动机本质上是一棵带有失败链接的 Trie 树：
//   - children: 正常的字节转移（goto 函数）
//   - fail: 匹配失败时的回退目标（failure 函数）
//   - output: 在此节点完成匹配的所有模式（output 函数，已合并 fail 链上的输出）
type acNode struct {
	children map[byte]*acNode // 子节点映射：字节值 -> 子节点指针
	fail     *acNode          // 失败链接：当前状态无法匹配时跳转到的最长后缀状态
	output   []HeaderEntry    // 输出列表：在此节点匹配完成的所有模式（含 fail 链合并）
	depth    int              // 节点深度（从根到此节点的路径长度，即已匹配的字节数）
}

// AhoCorasick 多模式匹配自动机
//
// 使用流程：
//  1. 调用 NewAhoCorasick() 创建空自动机
//  2. 调用 AddPattern() 逐个添加所有搜索模式
//  3. 调用 Build() 构建失败链接（必须在搜索前调用）
//  4. 调用 Search() 或 SearchStream() 执行搜索
type AhoCorasick struct {
	root  *acNode // 自动机根节点（初始状态）
	built bool    // 标记是否已调用 Build() 构建失败链接
}

// NewAhoCorasick 创建一个空的 Aho-Corasick 自动机
func NewAhoCorasick() *AhoCorasick {
	return &AhoCorasick{
		root: &acNode{
			children: make(map[byte]*acNode),
		},
	}
}

// AddPattern 向自动机的 Trie 树中添加一个搜索模式
//
// 参数:
//   - pattern: 要匹配的字节模式（如文件签名的 header 魔术字节）
//   - sig: 该模式对应的文件签名定义
//
// 注意:
//   - 添加完所有模式后，必须调用 Build() 才能进行搜索
//   - 同一个签名可以有多个 pattern（如 JPEG 有 5 种 header 变体）
//   - 不同签名也可以共享相同前缀（如 AAC 的 FFF1 和 MP3 的 FFFB 共享 FF 前缀）
//   - 空模式会被忽略
func (ac *AhoCorasick) AddPattern(pattern []byte, sig *types.FileSignature) {
	if len(pattern) == 0 {
		return
	}

	// 沿 Trie 树逐字节向下，不存在的节点就创建
	node := ac.root
	for _, b := range pattern {
		child, exists := node.children[b]
		if !exists {
			child = &acNode{
				children: make(map[byte]*acNode),
				depth:    node.depth + 1,
			}
			node.children[b] = child
		}
		node = child
	}

	// 在终止节点上记录匹配的模式（一个节点可能对应多个模式）
	node.output = append(node.output, HeaderEntry{
		Pattern:   pattern,
		Signature: sig,
	})
}

// Build 构建失败链接（failure links）和输出合并
//
// 算法步骤：
//  1. 使用 BFS（广度优先搜索）从根节点开始逐层遍历 Trie 树
//  2. 根节点的直接子节点（深度1）：fail 统一指向 root
//  3. 更深层的节点：沿父节点的 fail 链，查找具有相同字节转移的最长后缀
//  4. 输出合并：将 fail 节点的 output 追加到当前节点，实现"字典后缀链接"
//
// 输出合并的意义：
//
//	搜索时只需检查当前节点的 output 即可获得所有匹配，
//	无需再沿 fail 链逐级收集，提高搜索效率。
//
// 本方法必须在所有 AddPattern 调用之后、任何 Search 调用之前执行。
func (ac *AhoCorasick) Build() {
	// BFS 队列
	queue := make([]*acNode, 0)

	// 第一层初始化：根节点的所有直接子节点的 fail 指向根
	// 这是因为深度为1的节点失败后，最长的可匹配后缀只能是空串（即根节点）
	for _, child := range ac.root.children {
		child.fail = ac.root
		queue = append(queue, child)
	}

	// BFS 逐层处理，确保处理某个节点时，其所有祖先的 fail 已构建完毕
	for len(queue) > 0 {
		// 出队当前节点
		current := queue[0]
		queue = queue[1:]

		// 遍历当前节点的所有子节点，为每个子节点构建 fail 链接
		for b, child := range current.children {
			// 子节点入队，等待后续处理其自身的子节点
			queue = append(queue, child)

			// 核心逻辑：为 child 寻找 fail 目标
			// 从 current 的 fail 开始，沿 fail 链向上查找，
			// 直到找到一个拥有字节 b 对应子节点的状态
			fail := current.fail
			for fail != nil && fail.children[b] == nil {
				fail = fail.fail
			}

			if fail == nil {
				// 沿 fail 链一直回溯到根都没找到匹配，child 的 fail 指向根
				child.fail = ac.root
			} else {
				// 找到了拥有字节 b 转移的状态，child 的 fail 指向该状态的子节点
				child.fail = fail.children[b]
				// 安全检查：防止 fail 指向自身形成死循环（理论上不会发生）
				if child.fail == child {
					child.fail = ac.root
				}
			}

			// 输出合并：将 fail 节点的所有输出追加到 child 的输出列表
			// 这实现了"字典后缀链接"优化：
			// 例如模式 "he" 和 "she" 同时存在时，匹配到 "she" 的终止节点
			// 会通过 fail 链自动包含 "he" 的输出
			if len(child.fail.output) > 0 {
				child.output = append(child.output, child.fail.output...)
			}
		}
	}

	ac.built = true
}

// Search 在数据中搜索所有匹配的文件签名
//
// 参数:
//   - data: 待搜索的字节数据（通常是从磁盘读取的一个数据块）
//   - baseOffset: data 在原始磁盘/文件中的起始偏移量（用于计算绝对偏移）
//
// 返回所有匹配结果的切片，每个 Match 包含：
//   - Offset: 匹配模式起始位置在原始数据源中的绝对偏移
//   - Signature: 匹配到的文件签名定义
//   - Pattern: 实际匹配到的字节模式
//
// 如需在发现匹配时立即处理（而非收集全部结果），请使用 SearchStream。
func (ac *AhoCorasick) Search(data []byte, baseOffset int64) []Match {
	var matches []Match
	ac.SearchStream(data, baseOffset, func(m Match) bool {
		matches = append(matches, m)
		return true // 继续搜索所有匹配
	})
	return matches
}

// SearchStream 流式搜索：逐字节扫描数据，每发现一个匹配即通过回调通知
//
// 参数:
//   - data: 待搜索的字节数据
//   - baseOffset: data 在原始磁盘/文件中的起始偏移量
//   - callback: 匹配回调函数
//     返回 true  → 继续搜索后续匹配
//     返回 false → 立即停止搜索（用于"找到第一个即停"等场景）
//
// 工作原理:
//  1. 从 root 状态开始，逐字节读取 data
//  2. 对每个字节 b，尝试 goto 转移（查找 children[b]）
//  3. 若 goto 失败，沿 fail 链回溯，直到找到可转移的状态或回到 root
//  4. 在每个到达的状态节点上，遍历 output 中的所有匹配模式
//  5. 匹配的绝对偏移 = baseOffset + 当前扫描位置 - 模式长度 + 1
//
// 注意:
//   - 必须先调用 Build() 构建失败链接，否则本方法直接返回
//   - 所有字节 0x00-0xFF 都是有效的匹配字符（二进制安全）
//   - 对于同一位置的多个匹配（如不同长度的模式共享后缀），都会被报告
func (ac *AhoCorasick) SearchStream(data []byte, baseOffset int64, callback func(Match) bool) {
	// 安全检查：未构建失败链接时不执行搜索
	if !ac.built {
		return
	}

	// 从根节点（初始状态）开始
	node := ac.root

	for i, b := range data {
		// 步骤 1: 沿 fail 链回溯，直到找到具有字节 b 转移的状态
		// 如果当前节点没有字节 b 的子节点，就跟随 fail 链回退
		// 循环终止条件：到达 root（root 的 fail 为 nil，且我们检查 node != root）
		for node != ac.root && node.children[b] == nil {
			node = node.fail
		}

		// 步骤 2: 尝试 goto 转移
		if next, ok := node.children[b]; ok {
			node = next
		}
		// else: 当前在 root 且 root 也没有字节 b 的转移，保持在 root

		// 步骤 3: 收集当前状态的所有输出匹配
		// output 已在 Build() 阶段合并了 fail 链上的所有输出，
		// 所以只需检查当前节点的 output 即可
		if len(node.output) > 0 {
			for _, entry := range node.output {
				// 计算匹配模式在原始数据源中的绝对起始偏移
				// i 是匹配模式最后一个字节在 data 中的索引
				// 所以模式起始位置 = i - len(pattern) + 1
				// 绝对偏移 = baseOffset + 模式起始位置
				offset := baseOffset + int64(i) - int64(len(entry.Pattern)) + 1

				if !callback(Match{
					Offset:    offset,
					Signature: entry.Signature,
					Pattern:   entry.Pattern,
				}) {
					return // 回调返回 false，立即停止搜索
				}
			}
		}
	}
}
