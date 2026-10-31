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
//	         /dev/hd4         /                jfs2     ...       rw,log=/dev/hd8
//	         /dev/hd1         /home            jfs2     ...       rw,log=/dev/hd8
//	host     /remote/path     /mnt/nfs         nfs      ...       rw
//
// The "node" column is blank for local (non-NFS) mounts, which makes a naive
// fixed-column split unreliable. We use the column headers to locate the field
// boundaries from the separator line of dashes.
func parseMountTable(filter FilterFunc) ([]*Info, error) {
	out, err := exec.Command("/usr/sbin/mount").Output()
	if err != nil {
		return nil, fmt.Errorf("mountinfo: /usr/sbin/mount: %w", err)
	}
	return parseMountOutput(out, filter)
}

// parseMountOutput is factored out for testability.
func parseMountOutput(data []byte, filter FilterFunc) ([]*Info, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	// Skip the header line ("node  mounted  mounted over  vfs  ...").
	if !scanner.Scan() {
		return nil, nil
	}

	// The second line is a row of dashes that exactly mirrors the column widths.
	if !scanner.Scan() {
		return nil, nil
	}
	separator := scanner.Text()

	// Derive column start positions from the separator line.
	// Each column starts at the first '-' of each dash-group.
	type col struct{ start, end int }
	var cols []col
	inDash := false
	for i, c := range separator {
		switch {
		case c == '-' && !inDash:
			inDash = true
			cols = append(cols, col{start: i})
		case c != '-' && inDash:
			inDash = false
			cols[len(cols)-1].end = i
		}
	}
	if inDash {
		cols[len(cols)-1].end = len(separator)
	}

	// We need at least: node, mounted, mounted-over, vfs, date, options.
	// Columns: 0=node, 1=mounted(source), 2=mounted-over(target), 3=vfs(type), 4=date, 5=options
	if len(cols) < 4 {
		return nil, fmt.Errorf("mountinfo: unexpected /usr/sbin/mount column layout: %q", separator)
	}

	field := func(line string, c col) string {
		end := c.end
		if end > len(line) {
			end = len(line)
		}
		if c.start >= len(line) {
			return ""
		}
		return strings.TrimSpace(line[c.start:end])
	}

	var infos []*Info
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		// col 1 = source device/path, col 2 = mountpoint, col 3 = vfs type
		source := field(line, cols[1])
		mountpoint := field(line, cols[2])
		fstype := field(line, cols[3])
		var options string
		if len(cols) >= 6 {
			options = field(line, cols[5])
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

// mounted reports whether the given path is a mount point by checking whether
// its device differs from its parent's — the same stat-based heuristic used by
// the unix backend. Works for namefs because each namefs mount is a distinct
// vnode with its own device number.
func mounted(path string) (bool, error) {
	entries, err := GetMounts(SingleEntryFilter(path))
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}
