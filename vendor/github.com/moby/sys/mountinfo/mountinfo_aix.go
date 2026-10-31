//go:build aix
// +build aix

package mountinfo

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// parseMountTable parses the AIX mount table by running /usr/sbin/mount and
// applies the optional filter.
//
// AIX /usr/sbin/mount output (without arguments) looks like:
//
//	  node       mounted        mounted over  vfs       date        options
//	-------- ---------------  ---------------  -------  --------  ---------------
//	         /dev/hd4         /                jfs2     Jul  4 12:00   rw,log=/dev/hd8
//	         /dev/hd1         /home            jfs2     Jul  4 12:00   rw,log=/dev/hd8
//	host     /remote/path     /mnt/nfs         nfs      Jul  4 12:00   rw
//
// The "node" column is blank for local (non-NFS) mounts, and values longer
// than their column header push subsequent fields to the right, making
// fixed-column parsing unreliable for long mount points. We split on whitespace
// instead (the only robust approach on AIX):
//   - A line that starts with whitespace has no node entry.
//   - The date is always three words (month day time); options follow.
func parseMountTable(filter FilterFunc) ([]*Info, error) {
	out, err := exec.Command("/usr/sbin/mount").Output()
	if err != nil {
		return nil, fmt.Errorf("mountinfo: /usr/sbin/mount: %w", err)
	}
	return parseMountOutput(out, filter)
}

// parseMountOutput is factored out for testability.
//
// Field layout after whitespace-splitting:
//   - Line starts with whitespace (no NFS node):
//     [0]=source  [1]=mountpoint  [2]=vfs  [3..5]=date  [6..]=options
//   - Line starts with non-whitespace (NFS node present):
//     [0]=node  [1]=source  [2]=mountpoint  [3]=vfs  [4..6]=date  [7..]=options
func parseMountOutput(data []byte, filter FilterFunc) ([]*Info, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	// Skip the header line and the separator line of dashes.
	if !scanner.Scan() || !scanner.Scan() {
		return nil, nil
	}

	var infos []*Info
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Detect whether a node (NFS server) is present by checking whether
		// the line starts with whitespace.
		hasNode := len(line) > 0 && line[0] != ' ' && line[0] != '\t'

		fields := strings.Fields(line)

		// Minimum fields required: source, mountpoint, vfs, and 3 date words.
		// With node: 7 fields minimum. Without node: 6 fields minimum.
		minFields := 6
		if hasNode {
			minFields = 7
		}
		if len(fields) < minFields {
			continue
		}

		var source, mountpoint, fstype string
		var optionsIdx int
		if hasNode {
			// fields: [node, source, mountpoint, vfs, d1, d2, d3, options...]
			source = fields[1]
			mountpoint = fields[2]
			fstype = fields[3]
			optionsIdx = 7
		} else {
			// fields: [source, mountpoint, vfs, d1, d2, d3, options...]
			source = fields[0]
			mountpoint = fields[1]
			fstype = fields[2]
			optionsIdx = 6
		}

		var options string
		if len(fields) > optionsIdx {
			options = strings.Join(fields[optionsIdx:], ",")
		}

		if source == "" || mountpoint == "" {
			continue
		}

		m := &Info{
			Mountpoint: mountpoint,
			FSType:     fstype,
			Source:     source,
			Options:    options,
		}

		if filter != nil {
			skip, stop := filter(m)
			if skip {
				if stop {
					break
				}
				continue
			}
		}

		infos = append(infos, m)
	}
	return infos, scanner.Err()
}

// mounted reports whether the given path is a mount point by checking the
// mount table for an exact mountpoint match.
func mounted(path string) (bool, error) {
	entries, err := GetMounts(SingleEntryFilter(path))
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}
