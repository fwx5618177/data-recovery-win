package netfs

import "os"

// 把 os.Hostname 包一层便于测试时替换。
func osHostname() (string, error) { return os.Hostname() }
