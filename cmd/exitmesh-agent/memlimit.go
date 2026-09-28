package main

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// memoryHeadroom leaves 10 percent of the cgroup limit to non-heap memory.
const memoryHeadroom = 0.10

// v1 reports "no limit" as a page-rounded maximum int64.
const v1Unlimited = int64(1) << 62

// applyMemoryLimit sets GOMEMLIMIT from the cgroup memory limit when the environment does not set it.
func applyMemoryLimit(getenv func(string) string, procCgroup, cgroupRoot string) (int64, string, bool) {
	if getenv("GOMEMLIMIT") != "" {
		return 0, "", false
	}
	limit, source, ok := cgroupMemoryLimit(procCgroup, cgroupRoot)
	if !ok {
		return 0, "", false
	}
	soft := int64(float64(limit) * (1 - memoryHeadroom))
	debug.SetMemoryLimit(soft)
	return soft, source, true
}

// cgroupMemoryLimit returns the tightest memory limit of this process's cgroup and its ancestors (v2 memory.max, else v1 memory.limit_in_bytes).
func cgroupMemoryLimit(procCgroup, root string) (int64, string, bool) {
	f, err := os.Open(procCgroup)
	if err != nil {
		return 0, "", false
	}
	defer f.Close()
	var v2, v1 string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			v2 = parts[2]
		case hasController(parts[1], "memory"):
			v1 = parts[2]
		}
	}
	if v2 != "" {
		if l, src, ok := walkLimit(root, v2, "memory.max"); ok {
			return l, src, true
		}
	}
	if v1 != "" {
		return walkLimit(filepath.Join(root, "memory"), v1, "memory.limit_in_bytes")
	}
	return 0, "", false
}

func hasController(list, name string) bool {
	for _, c := range strings.Split(list, ",") {
		if c == name {
			return true
		}
	}
	return false
}

// walkLimit reads file in the cgroup directory and each ancestor up to the mount root.
func walkLimit(root, cg, file string) (int64, string, bool) {
	best, src, found := int64(0), "", false
	for p := path.Clean("/" + cg); ; p = path.Dir(p) {
		full := filepath.Join(root, p, file)
		if v, ok := readLimit(full); ok && (!found || v < best) {
			best, src, found = v, full, true
		}
		if p == "/" {
			break
		}
	}
	return best, src, found
}

func readLimit(p string) (int64, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 || v >= v1Unlimited {
		return 0, false
	}
	return v, true
}
