package userutil

import (
	"os/user"
	"strconv"
)

// ResolveUsername 通过 UID 查找用户名，带缓存避免重复 syscall。
func ResolveUsername(uid int, cache map[int]string) string {
	if name, ok := cache[uid]; ok {
		return name
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		cache[uid] = ""
		return ""
	}
	cache[uid] = u.Username
	return u.Username
}
