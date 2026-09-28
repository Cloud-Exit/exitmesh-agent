package hostfacts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	kubeletComms      = []string{"kubelet", "kubelite"}
	kubeletStateFiles = []string{
		"var/lib/kubelet/config.yaml",
		"etc/kubernetes/kubelet.conf",
		"var/lib/rancher/k3s/agent/kubelet.kubeconfig",
		"var/lib/rancher/rke2/agent/kubelet.kubeconfig",
	}
)

// IsKubernetesNode reports whether this host runs a kubelet or holds kubelet state, with the evidence; host mode then refuses to start.
func IsKubernetesNode(procRoot, fsRoot string) (bool, string, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return false, "", err
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(b))
		for _, k := range kubeletComms {
			if comm == k {
				return true, "process " + e.Name() + " (" + comm + ") is running", nil
			}
		}
	}
	for _, f := range kubeletStateFiles {
		p := filepath.Join(fsRoot, f)
		_, err := os.Stat(p)
		switch {
		case err == nil:
			return true, "kubelet state " + p + " exists", nil
		case errors.Is(err, fs.ErrPermission):
			return true, "kubelet state directory " + filepath.Dir(p) + " exists but is not searchable", nil
		}
	}
	return false, "", nil
}
