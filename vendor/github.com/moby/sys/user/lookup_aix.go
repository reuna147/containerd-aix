//go:build aix

package user

import (
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Unix-specific path to the passwd and group formatted files.
const (
	unixPasswdPath = "/etc/passwd"
	unixGroupPath  = "/etc/group"
)

// LookupUser looks up a user by their username in /etc/passwd. If the user
// cannot be found (or there is no /etc/passwd file on the filesystem), then
// LookupUser returns an error.
func LookupUser(username string) (User, error) {
	return lookupUserFunc(func(u User) bool {
		return u.Name == username
	})
}

// LookupUid looks up a user by their user id in /etc/passwd. If the user cannot
// be found (or there is no /etc/passwd file on the filesystem), then LookupId
// returns an error.
func LookupUid(uid int) (User, error) {
	return lookupUserFunc(func(u User) bool {
		return u.Uid == uid
	})
}

func lookupUserFunc(filter func(u User) bool) (User, error) {
	passwd, err := GetPasswd()
	if err != nil {
		return User{}, err
	}
	defer passwd.Close()

	users, err := ParsePasswdFilter(passwd, filter)
	if err != nil {
		return User{}, err
	}

	if len(users) == 0 {
		return User{}, ErrNoPasswdEntries
	}

	return users[0], nil
}

// LookupGroup looks up a group by its name in /etc/group. If the group cannot
// be found (or there is no /etc/group file on the filesystem), then LookupGroup
// returns an error.
func LookupGroup(groupname string) (Group, error) {
	return lookupGroupFunc(func(g Group) bool {
		return g.Name == groupname
	})
}

// LookupGid looks up a group by its group id in /etc/group. If the group cannot
// be found (or there is no /etc/group file on the filesystem), then LookupGid
// returns an error.
func LookupGid(gid int) (Group, error) {
	return lookupGroupFunc(func(g Group) bool {
		return g.Gid == gid
	})
}

func lookupGroupFunc(filter func(g Group) bool) (Group, error) {
	group, err := GetGroup()
	if err != nil {
		return Group{}, err
	}
	defer group.Close()

	groups, err := ParseGroupFilter(group, filter)
	if err != nil {
		return Group{}, err
	}

	if len(groups) == 0 {
		return Group{}, ErrNoGroupEntries
	}

	return groups[0], nil
}

func GetPasswdPath() (string, error) {
	return unixPasswdPath, nil
}

func GetPasswd() (io.ReadCloser, error) {
	return os.Open(unixPasswdPath)
}

func GetGroupPath() (string, error) {
	return unixGroupPath, nil
}

func GetGroup() (io.ReadCloser, error) {
	return os.Open(unixGroupPath)
}

// CurrentUser looks up the current user by their user id in /etc/passwd.
func CurrentUser() (User, error) {
	return LookupUid(unix.Getuid())
}

// CurrentGroup looks up the current user's group by their primary group id.
func CurrentGroup() (Group, error) {
	return LookupGid(unix.Getgid())
}

func currentUserSubIDs(fileName string) ([]SubID, error) {
	u, err := CurrentUser()
	if err != nil {
		return nil, err
	}
	filter := func(entry SubID) bool {
		return entry.Name == u.Name || entry.Name == strconv.Itoa(u.Uid)
	}
	return ParseSubIDFileFilter(fileName, filter)
}

func CurrentUserSubUIDs() ([]SubID, error) {
	return currentUserSubIDs("/etc/subuid")
}

func CurrentUserSubGIDs() ([]SubID, error) {
	return currentUserSubIDs("/etc/subgid")
}

func CurrentProcessUIDMap() ([]IDMap, error) {
	return ParseIDMapFile("/proc/self/uid_map")
}

func CurrentProcessGIDMap() ([]IDMap, error) {
	return ParseIDMapFile("/proc/self/gid_map")
}
