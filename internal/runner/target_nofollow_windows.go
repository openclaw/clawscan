//go:build windows

package runner

// Windows has no portable O_NOFOLLOW open flag, so the open itself may follow
// a reparse point. The leading lstat regular-file guard rejects a symlinked
// manifest before any open, and the post-open same-file identity check in
// readPluginID fails closed if the manifest is swapped for a symlink between
// those steps; the open-time traversal window itself is not eliminated on
// Windows.
const openNoFollowFlag = 0
