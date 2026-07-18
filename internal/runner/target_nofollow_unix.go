//go:build !windows

package runner

import "syscall"

// openNoFollowFlag refuses to open the final path component if it is a symlink,
// closing the window where an untrusted target swaps a regular manifest for a
// symlink between classification and read.
const openNoFollowFlag = syscall.O_NOFOLLOW
