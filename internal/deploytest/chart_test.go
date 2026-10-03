package deploytest

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
)

const (
	nodeDS    = "exitmesh-agent-node"
	cleanupDS = "exitmesh-agent-cleanup"
	coordName = "exitmesh-agent-coordinator"
)

var forbiddenResources = []string{
	"secrets", "nodes/proxy", "nodes/log", "pods/exec", "pods/attach", "pods/portforward", "pods/proxy",
	"services/proxy", "tokenreviews", "subjectaccessreviews", "selfsubjectaccessreviews",
	"localsubjectaccessreviews", "serviceaccounts/token", "*",
}

func TestEveryObjectMatchesAPISchema(t *testing.T) {
	for _, vs := range valueSets(t) {
		t.Run(vs.name, func(t *testing.T) {
			m := render(t, vs.args...)
			for _, o := range m.objects {
				var into any
				switch o["kind"] {
				case "Namespace":
					into = &corev1.Namespace{}
				case "ServiceAccount":
					into = &corev1.ServiceAccount{}
				case "Secret":
					into = &corev1.Secret{}
				case "ConfigMap":
					into = &corev1.ConfigMap{}
				case "Service":
					into = &corev1.Service{}
				case "DaemonSet":
					into = &appsv1.DaemonSet{}
				case "StatefulSet":
					into = &appsv1.StatefulSet{}
				case "ClusterRole", "Role":
					into = &rbacv1.ClusterRole{}
				case "ClusterRoleBinding", "RoleBinding":
					into = &rbacv1.ClusterRoleBinding{}
				case "NetworkPolicy":
					into = &networkingv1.NetworkPolicy{}
				case "Certificate":
					if o["apiVersion"] != "cert-manager.io/v1" {
						t.Fatalf("unexpected Certificate apiVersion %v", o["apiVersion"])
					}
					continue
				default:
					t.Fatalf("unexpected kind %v", o["kind"])
				}
				typed(t, o, into)
			}
		})
	}
}

func walk(v any, fn func(key string, val any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			fn(k, val)
			walk(val, fn)
		}
	case []any:
		for _, e := range x {
			walk(e, fn)
		}
	}
}

func TestNeverPrivileged(t *testing.T) {
	for _, vs := range valueSets(t) {
		m := render(t, vs.args...)
		for _, o := range m.objects {
			walk(o, func(k string, v any) {
				if (k == "privileged" || k == "hostNetwork" || k == "hostPID" || k == "hostIPC") && v == true {
					t.Errorf("%s: %s %s sets %s: true", vs.name, o["kind"], str(o, "metadata", "name"), k)
				}
				if k == "hostPort" {
					t.Errorf("%s: %s uses a hostPort", vs.name, str(o, "metadata", "name"))
				}
			})
		}
	}
}

func rules(t *testing.T, m *manifest) map[string][]rbacv1.PolicyRule {
	out := map[string][]rbacv1.PolicyRule{}
	for _, kind := range []string{"ClusterRole", "Role"} {
		for _, o := range m.all(kind) {
			var r rbacv1.ClusterRole
			typed(t, o, &r)
			out[kind+"/"+r.Namespace+"/"+r.Name] = r.Rules
		}
	}
	return out
}

func TestRBACIsReadOnly(t *testing.T) {
	for _, vs := range valueSets(t) {
		m := render(t, vs.args...)
		for name, rs := range rules(t, m) {
			for _, r := range rs {
				for _, verb := range r.Verbs {
					if verb != "get" && verb != "list" && verb != "watch" {
						t.Errorf("%s: %s grants verb %q", vs.name, name, verb)
					}
				}
				broadInventory := strings.HasSuffix(name, "-inventory") && reflect.DeepEqual(r.APIGroups, []string{"*"}) && reflect.DeepEqual(r.Resources, []string{"*"}) && reflect.DeepEqual(r.Verbs, []string{"list", "watch"})
				for _, g := range r.APIGroups {
					if g == "*" && !broadInventory {
						t.Errorf("%s: %s uses a wildcard apiGroup", vs.name, name)
					}
				}
				for _, res := range r.Resources {
					if slices.Contains(forbiddenResources, res) && !broadInventory {
						t.Errorf("%s: %s grants forbidden resource %q", vs.name, name, res)
					}
					if strings.Contains(res, "/") && res != "nodes/metrics" {
						t.Errorf("%s: %s grants subresource %q", vs.name, name, res)
					}
					if res == "nodes/metrics" && !reflect.DeepEqual(r.Verbs, []string{"get"}) {
						t.Errorf("%s: nodes/metrics must be get only, got %v", vs.name, r.Verbs)
					}
					if res == "persistentvolumes" && strings.HasSuffix(name, "/"+coordName) && !reflect.DeepEqual(r.Verbs, []string{"get"}) {
						t.Errorf("%s: coordinator base role must be get only", vs.name)
					}
				}
				for _, u := range r.NonResourceURLs {
					if u != "/.well-known/openid-configuration" && u != "/openid/v1/jwks" {
						t.Errorf("%s: %s grants non-resource URL %q", vs.name, name, u)
					}
				}
			}
		}
	}
}

func TestRBACPerCapability(t *testing.T) {
	m := render(t, baseArgs...)
	rs := rules(t, m)
	inv := rs["ClusterRole//"+coordName+"-inventory"]
	if len(inv) == 0 {
		t.Fatal("inventory ClusterRole missing")
	}
	granted := map[string]bool{}
	for _, r := range inv {
		if slices.Contains(r.Verbs, "list") && slices.Contains(r.Verbs, "watch") {
			for _, g := range r.APIGroups {
				for _, res := range r.Resources {
					granted[g+"/"+res] = true
				}
			}
		}
	}
	for _, k := range state.Catalog() {
		if !granted[k.GVR.Group+"/"+k.GVR.Resource] && !granted["*/*"] {
			t.Errorf("the coordinator collects %s by default but the inventory ClusterRole does not grant list and watch on %s", k.Kind, k.GVR.GroupResource())
		}
	}
	if got := rs["ClusterRole//"+nodeDS+"-metrics"]; len(got) != 1 || !reflect.DeepEqual(got[0].Resources, []string{"nodes/metrics"}) {
		t.Fatalf("metrics ClusterRole = %+v", got)
	}
	if got := rs["ClusterRole//"+nodeDS+"-pods"]; len(got) != 1 || !reflect.DeepEqual(got[0].Verbs, []string{"list", "watch"}) || !reflect.DeepEqual(got[0].Resources, []string{"pods"}) {
		t.Fatalf("node pods ClusterRole = %+v", got)
	}
	base := rs["ClusterRole//"+coordName]
	if len(base) != 1 || !reflect.DeepEqual(base[0].Resources, []string{"nodes", "persistentvolumes"}) {
		t.Fatalf("coordinator base ClusterRole = %+v", base)
	}
	if got := rs["Role/exitmesh-node/"+coordName+"-node-identity"]; len(got) != 1 || !reflect.DeepEqual(got[0].Verbs, []string{"get"}) {
		t.Fatalf("coordinator node identity Role = %+v", got)
	}

	m = render(t, append([]string{"--set", "capabilities.inventory=false", "--set", "capabilities.metrics=false"}, baseArgs...)...)
	if m.has("ClusterRole", coordName+"-inventory") || m.has("ClusterRole", nodeDS+"-metrics") {
		t.Fatal("disabled capabilities still render their RBAC")
	}
}

func TestNamespaceScopedProfileRendersRoles(t *testing.T) {
	m := render(t, append([]string{"--set", "kubernetes.scope=namespaces", "--set", "kubernetes.namespaces={team-a,team-b}"}, baseArgs...)...)
	for _, ns := range []string{"team-a", "team-b"} {
		for _, n := range []string{coordName + "-inventory", nodeDS + "-pods"} {
			found := false
			for _, o := range m.all("Role") {
				if str(o, "metadata", "name") == n && str(o, "metadata", "namespace") == ns {
					found = true
				}
			}
			if !found {
				t.Errorf("Role %s missing in namespace %s", n, ns)
			}
			rbFound := false
			for _, o := range m.all("RoleBinding") {
				if str(o, "metadata", "name") == n && str(o, "metadata", "namespace") == ns {
					rbFound = true
				}
			}
			if !rbFound {
				t.Errorf("RoleBinding %s missing in namespace %s", n, ns)
			}
		}
	}
	nsRules := rules(t, m)
	for _, ns := range []string{"team-a", "team-b"} {
		if got := nsRules["Role/"+ns+"/"+nodeDS+"-pods"]; len(got) != 1 || !reflect.DeepEqual(got[0].Verbs, []string{"list", "watch"}) ||
			!reflect.DeepEqual(got[0].Resources, []string{"pods"}) || !reflect.DeepEqual(got[0].APIGroups, []string{""}) {
			t.Errorf("node pods Role in %s = %+v, want list and watch on pods for the per-namespace pod watch", ns, got)
		}
	}
	for name, rs := range nsRules {
		if name == "ClusterRole//"+coordName+"-discovery" {
			if len(rs) != 1 || !reflect.DeepEqual(rs[0].Resources, []string{"customresourcedefinitions"}) || !reflect.DeepEqual(rs[0].Verbs, []string{"list", "watch"}) {
				t.Fatal("invalid CRD discovery permission")
			}
			continue
		}
		if !strings.HasPrefix(name, "ClusterRole/") {
			continue
		}
		for _, r := range rs {
			for _, res := range r.Resources {
				if res != "nodes" && res != "persistentvolumes" && res != "nodes/metrics" {
					t.Errorf("namespace profile ClusterRole %s grants %q", name, res)
				}
			}
			if !reflect.DeepEqual(r.Verbs, []string{"get"}) {
				t.Errorf("namespace profile ClusterRole %s grants %v", name, r.Verbs)
			}
		}
	}
	m = render(t, append([]string{"--set", "kubernetes.scope=namespaces", "--set", "kubernetes.namespaces={team-a}", "--set", "rbac.clusterReads=false"}, baseArgs...)...)
	if n := len(m.all("ClusterRole")) + len(m.all("ClusterRoleBinding")); n != 2 {
		t.Fatalf("namespace profile without cluster reads rendered %d cluster-scoped RBAC objects", n)
	}
	renderFails(t, "requires kubernetes.namespaces", append([]string{"--set", "kubernetes.scope=namespaces"}, baseArgs...)...)
}

func containerByName(cs []corev1.Container, name string) *corev1.Container {
	for i := range cs {
		if cs[i].Name == name {
			return &cs[i]
		}
	}
	return nil
}

func TestNodeAgentSecurityContext(t *testing.T) {
	m := render(t, baseArgs...)
	ds := daemonSet(t, m, nodeDS)
	c := containerByName(ds.Spec.Template.Spec.Containers, "node-agent")
	if c == nil || len(ds.Spec.Template.Spec.Containers) != 1 {
		t.Fatal("node-agent container missing")
	}
	sc := c.SecurityContext
	if sc == nil || sc.Capabilities == nil {
		t.Fatal("node-agent securityContext missing")
	}
	// SETGID and SETUID only let the agent switch to UID 65532; the running agent keeps CAP_DAC_READ_SEARCH alone.
	if !reflect.DeepEqual(sc.Capabilities.Add, []corev1.Capability{"DAC_READ_SEARCH", "SETGID", "SETUID"}) || !reflect.DeepEqual(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		t.Fatalf("capabilities = %+v", sc.Capabilities)
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("root filesystem must be read-only")
	}
	if sc.RunAsUser == nil || *sc.RunAsUser != 0 || sc.RunAsNonRoot == nil || *sc.RunAsNonRoot {
		t.Error("node agent must start as root to switch to UID 65532 with CAP_DAC_READ_SEARCH")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("allowPrivilegeEscalation must be false")
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("seccomp must be RuntimeDefault")
	}
	if len(ds.Spec.Template.Spec.InitContainers) != 1 {
		t.Fatal("expected one init container")
	}
	ic := ds.Spec.Template.Spec.InitContainers[0]
	if !reflect.DeepEqual(ic.SecurityContext.Capabilities.Add, []corev1.Capability{"CHOWN"}) || *ic.SecurityContext.RunAsUser != 0 {
		t.Fatalf("init container must run as root with only CAP_CHOWN: %+v", ic.SecurityContext)
	}
	if !reflect.DeepEqual(ic.Args, []string{"prepare-state", "--dir", "/var/lib/exitmesh", "--uid", "65532", "--gid", "65532"}) {
		t.Fatalf("init args = %v", ic.Args)
	}
	if !reflect.DeepEqual(c.Args, []string{"run", "--config", "/etc/exitmesh/config/agent.yaml", "--run-as", "65532:65532"}) {
		t.Fatalf("args = %v", c.Args)
	}
	if ds.Spec.UpdateStrategy.RollingUpdate == nil || ds.Spec.UpdateStrategy.RollingUpdate.MaxSurge.IntValue() != 0 {
		t.Error("node agent rolling update must not surge (one writer per node directory)")
	}
	req, lim := c.Resources.Requests, c.Resources.Limits
	if req.Cpu().String() != "100m" || req.Memory().String() != "192Mi" || lim.Cpu().String() != "100m" || lim.Memory().String() != "192Mi" {
		t.Errorf("resources = %+v", c.Resources)
	}
	env := map[string]corev1.EnvVar{}
	for _, e := range c.Env {
		env[e.Name] = e
	}
	for name, path := range map[string]string{"NODE_NAME": "spec.nodeName", "POD_NAME": "metadata.name", "NODE_IP": "status.hostIP"} {
		if e, ok := env[name]; !ok || e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != path {
			t.Errorf("env %s must come from the downward API field %s", name, path)
		}
	}
	lm := env["EXITMESH_MEMORY_LIMIT_MIB"]
	if lm.ValueFrom == nil || lm.ValueFrom.ResourceFieldRef == nil || lm.ValueFrom.ResourceFieldRef.Resource != "limits.memory" || lm.ValueFrom.ResourceFieldRef.Divisor.String() != "1Mi" {
		t.Error("memory limit must come from resourceFieldRef limits.memory")
	}
	if env["GOMEMLIMIT"].Value != "$(EXITMESH_MEMORY_LIMIT_MIB)000KiB" {
		t.Errorf("GOMEMLIMIT = %q", env["GOMEMLIMIT"].Value)
	}

	fb := daemonSet(t, render(t, append([]string{"--set", "node.runAsRootFallback=true"}, baseArgs...)...), nodeDS)
	fc := fb.Spec.Template.Spec.Containers[0].SecurityContext
	if *fc.RunAsUser != 0 || *fc.RunAsNonRoot || fb.Spec.Template.Annotations["exitmesh.io/run-as-root-fallback"] != "true" {
		t.Fatal("root fallback must run as UID 0 and be flagged")
	}
	if !reflect.DeepEqual(fc.Capabilities.Add, []corev1.Capability{"DAC_READ_SEARCH"}) {
		t.Fatal("root fallback must hold CAP_DAC_READ_SEARCH alone")
	}
	if args := fb.Spec.Template.Spec.Containers[0].Args; slices.Contains(args, "--run-as") {
		t.Fatalf("root fallback must not switch users: %v", args)
	}
	custom := daemonSet(t, render(t, append([]string{"--set", "node.uid=4000", "--set", "node.gid=4001"}, baseArgs...)...), nodeDS)
	if args := custom.Spec.Template.Spec.Containers[0].Args; !slices.Equal(args[len(args)-2:], []string{"--run-as", "4000:4001"}) {
		t.Fatalf("custom identity args = %v", args)
	}
}

func hostPaths(spec corev1.PodSpec) map[string]*corev1.HostPathVolumeSource {
	out := map[string]*corev1.HostPathVolumeSource{}
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			out[v.Name] = v.HostPath
		}
	}
	return out
}

func TestHostPaths(t *testing.T) {
	for _, vs := range valueSets(t) {
		m := render(t, vs.args...)
		for _, o := range m.all("DaemonSet") {
			var ds appsv1.DaemonSet
			typed(t, o, &ds)
			spec := ds.Spec.Template.Spec
			hp := hostPaths(spec)
			for name, h := range hp {
				switch h.Path {
				case "/var/lib/exitmesh":
					if h.Type == nil || *h.Type != corev1.HostPathDirectoryOrCreate {
						t.Errorf("%s: /var/lib/exitmesh must be DirectoryOrCreate", vs.name)
					}
				case "/var/log/pods":
					if ds.Name != nodeDS {
						t.Errorf("%s: %s mounts /var/log/pods", vs.name, ds.Name)
					}
					for _, c := range append(spec.InitContainers, spec.Containers...) {
						for _, vm := range c.VolumeMounts {
							if vm.Name == name && !vm.ReadOnly {
								t.Errorf("%s: /var/log/pods must be mounted read-only", vs.name)
							}
						}
					}
				default:
					t.Errorf("%s: %s uses unexpected hostPath %s", vs.name, ds.Name, h.Path)
				}
			}
		}
		for _, o := range m.all("StatefulSet") {
			var s appsv1.StatefulSet
			typed(t, o, &s)
			if len(hostPaths(s.Spec.Template.Spec)) != 0 {
				t.Errorf("%s: coordinator must not use hostPath", vs.name)
			}
		}
	}
	logsOff := daemonSet(t, render(t, append([]string{"--set", "capabilities.logs=false"}, baseArgs...)...), nodeDS)
	for _, h := range hostPaths(logsOff.Spec.Template.Spec) {
		if h.Path == "/var/log/pods" {
			t.Fatal("/var/log/pods mounted without the logs capability")
		}
	}
	on := daemonSet(t, render(t, baseArgs...), nodeDS)
	paths := []string{}
	for _, h := range hostPaths(on.Spec.Template.Spec) {
		paths = append(paths, h.Path)
	}
	slices.Sort(paths)
	if !reflect.DeepEqual(paths, []string{"/var/lib/exitmesh", "/var/log/pods"}) {
		t.Fatalf("node agent hostPaths = %v", paths)
	}
}

var restrictedVolumeTypes = func(v corev1.Volume) bool {
	s := v.VolumeSource
	return s.ConfigMap != nil || s.CSI != nil || s.DownwardAPI != nil || s.EmptyDir != nil || s.Ephemeral != nil || s.PersistentVolumeClaim != nil || s.Projected != nil || s.Secret != nil
}

func TestCoordinatorRestricted(t *testing.T) {
	for _, vs := range valueSets(t) {
		s := statefulSet(t, render(t, vs.args...))
		spec := s.Spec.Template.Spec
		if s.Spec.Replicas == nil || *s.Spec.Replicas != 1 {
			t.Errorf("%s: coordinator replicas must be 1", vs.name)
		}
		rp := s.Spec.PersistentVolumeClaimRetentionPolicy
		if rp == nil || rp.WhenDeleted != appsv1.DeletePersistentVolumeClaimRetentionPolicyType {
			t.Errorf("%s: PVC retention whenDeleted must be Delete", vs.name)
		}
		if len(s.Spec.VolumeClaimTemplates) != 1 {
			t.Fatalf("%s: expected one volumeClaimTemplate", vs.name)
		}
		for _, am := range s.Spec.VolumeClaimTemplates[0].Spec.AccessModes {
			if am != corev1.ReadWriteOncePod && am != corev1.ReadWriteOnce {
				t.Errorf("%s: access mode %s", vs.name, am)
			}
		}
		psc := spec.SecurityContext
		if psc == nil || psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot || psc.SeccompProfile == nil || psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Errorf("%s: coordinator pod securityContext is not restricted", vs.name)
		}
		for _, v := range spec.Volumes {
			if !restrictedVolumeTypes(v) {
				t.Errorf("%s: volume %s is not allowed under restricted", vs.name, v.Name)
			}
		}
		for _, c := range append(spec.InitContainers, spec.Containers...) {
			sc := c.SecurityContext
			if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.Capabilities == nil ||
				!reflect.DeepEqual(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(sc.Capabilities.Add) != 0 ||
				sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				t.Errorf("%s: container %s securityContext is not restricted", vs.name, c.Name)
			}
			for _, p := range c.Ports {
				if p.HostPort != 0 {
					t.Errorf("%s: hostPort in coordinator", vs.name)
				}
			}
		}
	}
	def := statefulSet(t, render(t, baseArgs...))
	if got := def.Spec.VolumeClaimTemplates[0].Spec.AccessModes; !reflect.DeepEqual(got, []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod}) {
		t.Fatalf("default access modes = %v", got)
	}
	if def.Spec.VolumeClaimTemplates[0].Spec.StorageClassName != nil {
		t.Fatal("default must use the cluster default StorageClass")
	}
	sc := statefulSet(t, render(t, append([]string{"--set", "coordinator.persistence.storageClassName=fast"}, baseArgs...)...))
	if n := sc.Spec.VolumeClaimTemplates[0].Spec.StorageClassName; n == nil || *n != "fast" {
		t.Fatal("storageClassName not applied")
	}
	svc := m0(t).find(t, "Service", coordName)
	var s corev1.Service
	typed(t, svc, &s)
	if s.Spec.Type != corev1.ServiceTypeClusterIP || len(s.Spec.Ports) != 1 || s.Spec.Ports[0].Port != 8443 {
		t.Fatalf("coordinator Service = %+v", s.Spec)
	}
}

func m0(t *testing.T) *manifest { return render(t, baseArgs...) }

func TestAccessModesRejected(t *testing.T) {
	renderFails(t, "ReadWriteMany is refused", append([]string{"--set", "coordinator.persistence.accessMode=ReadWriteMany"}, baseArgs...)...)
	renderFails(t, "must be ReadWriteOncePod or ReadWriteOnce", append([]string{"--set", "coordinator.persistence.accessMode=ReadOnlyMany"}, baseArgs...)...)
}

func TestNamespaces(t *testing.T) {
	m := render(t, baseArgs...)
	want := map[string]string{"exitmesh-node": "privileged", "exitmesh": "restricted"}
	nss := m.all("Namespace")
	if len(nss) != 2 {
		t.Fatalf("rendered %d namespaces", len(nss))
	}
	for _, o := range nss {
		name := str(o, "metadata", "name")
		if got := str(o, "metadata", "labels", "pod-security.kubernetes.io/enforce"); got != want[name] {
			t.Errorf("namespace %s enforce=%q want %q", name, got, want[name])
		}
		if str(o, "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
			t.Errorf("namespace %s must be kept on uninstall", name)
		}
	}
	ds := daemonSet(t, m, nodeDS)
	if ds.Namespace != "exitmesh-node" || statefulSet(t, m).Namespace != "exitmesh" {
		t.Fatal("workloads rendered into the wrong namespaces")
	}
}

// Offline renders cannot run lookup, so createNamespaces=false fails unless acknowledged; docs/install-kubernetes.md covers the live-cluster checks.
func TestPrecreatedNamespaces(t *testing.T) {
	renderFails(t, "cannot verify namespaces", append([]string{"--set", "createNamespaces=false"}, baseArgs...)...)
	m := render(t, append([]string{"--set", "createNamespaces=false", "--set", "namespaces.skipLookupValidation=true"}, baseArgs...)...)
	if len(m.all("Namespace")) != 0 {
		t.Fatal("createNamespaces=false still renders Namespace objects")
	}
	renderFails(t, "must differ", append([]string{"--set", "namespaces.node=exitmesh"}, baseArgs...)...)
	full := append([]string{"template", "exitmesh-agent", chartDir(t), "--namespace", "exitmesh", "--set-json", `trust.roots=["` + testRoot + `"]`}, baseArgs...)
	out, err := runHelm(t, full...)
	if err == nil || !strings.Contains(out, "is one of the namespaces this chart creates") {
		t.Fatalf("release namespace equal to a chart namespace must fail: %v %s", err, out)
	}
}

func TestRequiredInputs(t *testing.T) {
	renderFails(t, "endpoint is required", "--set", "enrollment.token=emx1_c_t-1_s")
	schemaFails(t, "endpoint", "--set", "enrollment.token=emx1_c_t-1_s", "--set", "endpoint=http://insecure.example.com")
	schemaFails(t, "endpoint", "--set", "enrollment.token=emx1_c_t-1_s", "--set", "endpoint=https://:18443")
	renderFails(t, "an enrollment token is required", "--set", "endpoint=https://cp.example.com")
	schemaFails(t, "token", "--set", "endpoint=https://cp.example.com", "--set", "enrollment.token=abc")
	render(t, "--set", "enrollment.token=emx1_c_t-1_s", "--set", "airgap.enabled=true")
	renderFails(t, "at least one of capabilities", append([]string{"--set", "capabilities.inventory=false", "--set", "capabilities.metrics=false", "--set", "capabilities.logs=false"}, baseArgs...)...)
	renderFails(t, "requires tls.caBundle", append([]string{"--set", "tls.mode=existingSecret", "--set", "tls.existingSecret=x"}, baseArgs...)...)
	renderFails(t, "requires tls.certManager.issuerRef.name", append([]string{"--set", "tls.mode=certManager", "--set", "tls.caBundle=x"}, baseArgs...)...)
}

func TestInventoryOverridesCannotWiden(t *testing.T) {
	renderFails(t, "must not grant \"secrets\"", append([]string{"--set", "rbac.inventory.namespaced[0].apiGroups={}", "--set", "rbac.inventory.namespaced[0].resources={secrets}"}, baseArgs...)...)
	renderFails(t, "must not grant \"pods/exec\"", append([]string{"--set", "rbac.inventory.namespaced[0].apiGroups={}", "--set", "rbac.inventory.namespaced[0].resources={pods/exec}"}, baseArgs...)...)
	renderFails(t, "wildcard apiGroups", append([]string{"--set", "rbac.inventory.cluster[0].apiGroups={*}", "--set", "rbac.inventory.cluster[0].resources={nodes}"}, baseArgs...)...)
}

func TestProjectedTokenAndCoordinatorCA(t *testing.T) {
	m := render(t, baseArgs...)
	ds := daemonSet(t, m, nodeDS)
	var tok *corev1.ServiceAccountTokenProjection
	for _, v := range ds.Spec.Template.Spec.Volumes {
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.ServiceAccountToken != nil {
					tok = s.ServiceAccountToken
				}
			}
		}
	}
	if tok == nil || tok.Audience != "exitmesh-coordinator" || tok.ExpirationSeconds == nil || *tok.ExpirationSeconds != 600 || tok.Path != "token" {
		t.Fatalf("projected token = %+v", tok)
	}
	mounts := map[string]string{}
	for _, vm := range ds.Spec.Template.Spec.Containers[0].VolumeMounts {
		mounts[vm.Name] = vm.MountPath
	}
	if mounts["coordinator-token"] != "/var/run/secrets/exitmesh" || mounts["coordinator-ca"] != "/etc/exitmesh/coordinator-ca" {
		t.Fatalf("mounts = %v", mounts)
	}

	sec := m.find(t, "Secret", coordName+"-tls")
	var s corev1.Secret
	typed(t, sec, &s)
	if s.Type != corev1.SecretTypeTLS {
		t.Fatalf("TLS secret type %s", s.Type)
	}
	caPEM := string(s.Data["ca.crt"])
	var cm corev1.ConfigMap
	typed(t, m.find(t, "ConfigMap", coordName+"-ca"), &cm)
	if cm.Namespace != "exitmesh-node" || strings.TrimSpace(cm.Data["ca.crt"]) != strings.TrimSpace(caPEM) {
		t.Fatal("node agents must receive the CA that signed the coordinator certificate")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("ca.crt is not PEM")
	}
	blk, _ := pem.Decode(s.Data["tls.crt"])
	if blk == nil {
		t.Fatal("tls.crt is not PEM")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crt.Verify(x509.VerifyOptions{DNSName: coordName + ".exitmesh.svc", Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("serving certificate does not verify for the Service name: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(sec["data"].(map[string]any)["tls.key"].(string)); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkPolicies(t *testing.T) {
	m := render(t, baseArgs...)
	var node, coord networkingv1.NetworkPolicy
	typed(t, m.find(t, "NetworkPolicy", nodeDS), &node)
	typed(t, m.find(t, "NetworkPolicy", coordName), &coord)
	for _, np := range []networkingv1.NetworkPolicy{node, coord} {
		if !reflect.DeepEqual(np.Spec.PolicyTypes, []networkingv1.PolicyType{"Ingress", "Egress"}) {
			t.Errorf("%s policyTypes = %v", np.Name, np.Spec.PolicyTypes)
		}
	}
	if len(node.Spec.Ingress) != 0 {
		t.Error("node agents accept no ingress")
	}
	toCoord := false
	for _, e := range node.Spec.Egress {
		for _, p := range e.To {
			if p.NamespaceSelector != nil && p.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "exitmesh" && p.PodSelector != nil && p.PodSelector.MatchLabels["app.kubernetes.io/component"] == "coordinator" {
				toCoord = len(e.Ports) == 1 && e.Ports[0].Port.IntValue() == 8443
			}
		}
	}
	if !toCoord {
		t.Error("node agent egress to the coordinator Service port missing")
	}
	if len(coord.Spec.Ingress) != 1 || len(coord.Spec.Ingress[0].From) != 1 {
		t.Fatalf("coordinator ingress = %+v", coord.Spec.Ingress)
	}
	from := coord.Spec.Ingress[0].From[0]
	if from.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "exitmesh-node" || from.PodSelector.MatchLabels["app.kubernetes.io/component"] != "node" {
		t.Fatal("coordinator ingress must be limited to node agents")
	}
	ports := map[int]bool{}
	for _, e := range coord.Spec.Egress {
		for _, p := range e.Ports {
			ports[p.Port.IntValue()] = true
		}
	}
	for _, p := range []int{53, 443, 6443} {
		if !ports[p] {
			t.Errorf("coordinator egress lacks port %d", p)
		}
	}
	if m := render(t, append([]string{"--set", "networkPolicy.enabled=false"}, baseArgs...)...); len(m.all("NetworkPolicy")) != 0 {
		t.Fatal("networkPolicy.enabled=false still renders policies")
	}
}

func TestCleanupHook(t *testing.T) {
	m := render(t, baseArgs...)
	o := m.find(t, "DaemonSet", cleanupDS)
	if str(o, "metadata", "annotations", "helm.sh/hook") != "post-delete" {
		t.Fatal("cleanup DaemonSet must be a post-delete hook")
	}
	ds := daemonSet(t, m, cleanupDS)
	spec := ds.Spec.Template.Spec
	if ds.Namespace != "exitmesh-node" || spec.ServiceAccountName != "" || spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Fatal("cleanup pods must run without Kubernetes credentials in the node namespace")
	}
	if !reflect.DeepEqual(spec.InitContainers[0].Args, []string{"cleanup", "--dir", "/var/lib/exitmesh"}) || !reflect.DeepEqual(spec.Containers[0].Args, []string{"cleanup", "--dir", "/var/lib/exitmesh", "--wait"}) {
		t.Fatalf("cleanup args = %v %v", spec.InitContainers[0].Args, spec.Containers[0].Args)
	}
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		if len(c.SecurityContext.Capabilities.Add) != 0 || *c.SecurityContext.RunAsUser != 65532 {
			t.Errorf("cleanup container %s must run as the agent UID with no capabilities", c.Name)
		}
	}
	for _, k := range []string{"Job", "CronJob", "Pod"} {
		if len(m.all(k)) != 0 {
			t.Errorf("chart renders a %s", k)
		}
	}
}

func agentConfigs(t *testing.T, m *manifest) (coord, node *config.Config) {
	t.Helper()
	for _, name := range []string{coordName + "-config", nodeDS + "-config"} {
		var cm corev1.ConfigMap
		typed(t, m.find(t, "ConfigMap", name), &cm)
		c, err := config.Parse([]byte(cm.Data["agent.yaml"]))
		if err != nil {
			t.Fatalf("%s agent.yaml does not load: %v\n%s", name, err, cm.Data["agent.yaml"])
		}
		if name == coordName+"-config" {
			coord = c
		} else {
			node = c
		}
	}
	return coord, node
}

func TestRenderedConfigLoads(t *testing.T) {
	for _, vs := range valueSets(t) {
		t.Run(vs.name, func(t *testing.T) {
			m := render(t, vs.args...)
			coord, node := agentConfigs(t, m)
			if coord.Role != config.RoleCoordinator || node.Role != config.RoleNode {
				t.Fatal("roles not rendered")
			}
			if node.Coordinator.ServiceURL != "https://"+coordName+".exitmesh.svc:8443" || node.Coordinator.TokenFile != "/var/run/secrets/exitmesh/token" || node.Coordinator.Audience != "exitmesh-coordinator" {
				t.Fatalf("node coordinator section = %+v", node.Coordinator)
			}
			if node.StateDir != "/var/lib/exitmesh" || coord.StateDir != "/data" {
				t.Fatal("state directories")
			}
			if !reflect.DeepEqual(coord.Capabilities, node.Capabilities) {
				t.Fatal("capabilities differ between roles")
			}
		})
	}
	m := render(t, append([]string{"--set", "capabilities.inventory=false", "--set", "capabilities.logs=false"}, baseArgs...)...)
	coord, _ := agentConfigs(t, m)
	if !reflect.DeepEqual(coord.Capabilities, []string{"metrics"}) {
		t.Fatalf("capabilities = %v", coord.Capabilities)
	}
	ag := render(t, "--set", "enrollment.token=emx1_c_t-9_secret", "--set", "airgap.enabled=true", "--set", "airgap.bundles.configMap=exitmesh-bundles")
	coord, _ = agentConfigs(t, ag)
	if !coord.AirGap.Enabled || coord.AirGap.BundleDir != "/etc/exitmesh/bundles" || coord.AirGap.ExportDir != "/data/export" || coord.Spool.Capacity != 50<<30 {
		t.Fatalf("airgap config = %+v spool %d", coord.AirGap, coord.Spool.Capacity)
	}
	s := statefulSet(t, ag)
	if q := s.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests[corev1.ResourceStorage]; q.String() != "60Gi" {
		t.Fatalf("air-gap PVC size %s", q.String())
	}
	var bundleMounts []string
	for _, vm := range s.Spec.Template.Spec.Containers[0].VolumeMounts {
		if vm.Name == "bundles" {
			if vm.SubPath == "" || !vm.ReadOnly || vm.MountPath != "/etc/exitmesh/bundles/"+vm.SubPath {
				t.Errorf("bundle mount %+v must be a read-only subPath file", vm)
			}
			bundleMounts = append(bundleMounts, vm.SubPath)
		}
	}
	if !reflect.DeepEqual(bundleMounts, []string{"keymanifest.json", "bundle.tar.gz", "bundle.sig"}) {
		t.Fatalf("bundle files = %v", bundleMounts)
	}
}

func TestLookbackCredentialsMountedExplicitly(t *testing.T) {
	var full []string
	for _, vs := range valueSets(t) {
		if vs.name == "full" {
			full = vs.args
		}
	}
	m := render(t, full...)
	coord, _ := agentConfigs(t, m)
	if len(coord.Lookback) != 2 || coord.Lookback[0].BearerTokenFile != "/etc/exitmesh/lookback/mimir/bearer-token" || coord.Lookback[1].CAFile != "/etc/exitmesh/lookback/logs/ca.crt" {
		t.Fatalf("lookback = %+v", coord.Lookback)
	}
	s := statefulSet(t, m)
	var proj *corev1.ProjectedVolumeSource
	for _, v := range s.Spec.Template.Spec.Volumes {
		if v.Name == "lookback-credentials" {
			proj = v.Projected
		}
	}
	if proj == nil {
		t.Fatal("lookback credentials volume missing")
	}
	paths := []string{}
	for _, src := range proj.Sources {
		if src.Secret != nil {
			for _, it := range src.Secret.Items {
				paths = append(paths, src.Secret.Name+":"+it.Path)
			}
		}
		if src.ConfigMap != nil {
			for _, it := range src.ConfigMap.Items {
				paths = append(paths, src.ConfigMap.Name+":"+it.Path)
			}
		}
	}
	want := []string{"mimir-reader:mimir/bearer-token", "vl-auth:logs/username", "vl-auth:logs/password", "vl-ca:logs/ca.crt"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("credential items = %v", paths)
	}
	var np networkingv1.NetworkPolicy
	typed(t, m.find(t, "NetworkPolicy", coordName), &np)
	found := 0
	for _, e := range np.Spec.Egress {
		for _, p := range e.To {
			if p.IPBlock != nil && p.IPBlock.CIDR == "203.0.113.0/24" && e.Ports[0].Port.IntValue() == 443 {
				found++
			}
			if p.NamespaceSelector != nil && p.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "monitoring" && e.Ports[0].Port.IntValue() == 8080 {
				found++
			}
		}
	}
	if found != 2 {
		t.Fatal("lookback egress rules missing")
	}
}

func TestTrustRootsRequired(t *testing.T) {
	renderFails(t, "trust.roots is required", append([]string{"--set-json", "trust.roots=[]"}, baseArgs...)...)
	coord, node := agentConfigs(t, render(t, baseArgs...))
	if len(coord.Trust.Roots) != 1 || len(node.Trust.Roots) != 1 {
		t.Fatalf("trust roots not rendered: %+v %+v", coord.Trust, node.Trust)
	}
}

func TestCoordinatorKnowsNodeServiceAccount(t *testing.T) {
	m := render(t, baseArgs...)
	s := statefulSet(t, m)
	env := map[string]string{}
	for _, e := range s.Spec.Template.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	ds := daemonSet(t, m, nodeDS)
	if env["EXITMESH_NODE_SERVICE_ACCOUNT"] != ds.Spec.Template.Spec.ServiceAccountName || env["EXITMESH_NODE_NAMESPACE"] != ds.Namespace || ds.Namespace == "" {
		t.Fatalf("coordinator env %v does not name the node agent ServiceAccount %s/%s", env, ds.Namespace, ds.Spec.Template.Spec.ServiceAccountName)
	}
}

func TestCoordinatorEgressAllowsEndpointPort(t *testing.T) {
	m := render(t, "--set", "endpoint=https://cp.internal.example:9443", "--set", "enrollment.token=emx1_c_t-123_secret")
	var coord networkingv1.NetworkPolicy
	typed(t, m.find(t, "NetworkPolicy", coordName), &coord)
	ports := map[int]bool{}
	for _, e := range coord.Spec.Egress {
		for _, p := range e.Ports {
			ports[p.Port.IntValue()] = true
		}
	}
	if !ports[9443] || !ports[443] {
		t.Fatalf("coordinator egress ports %v must include the endpoint port 9443 and the default 443", ports)
	}
}
