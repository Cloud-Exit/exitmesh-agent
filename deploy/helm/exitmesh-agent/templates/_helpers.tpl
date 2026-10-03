{{- define "exitmesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "exitmesh.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "exitmesh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Call with (dict "ctx" $ "component" "node"). */}}
{{- define "exitmesh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "exitmesh.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "exitmesh.labels" -}}
{{ include "exitmesh.selectorLabels" . }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/part-of: exitmesh
helm.sh/chart: {{ include "exitmesh.chart" .ctx }}
{{- end -}}

{{- define "exitmesh.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "exitmesh.coordinatorName" -}}{{ include "exitmesh.fullname" . }}-coordinator{{- end -}}
{{- define "exitmesh.nodeName" -}}{{ include "exitmesh.fullname" . }}-node{{- end -}}
{{- define "exitmesh.cleanupName" -}}{{ include "exitmesh.fullname" . }}-cleanup{{- end -}}
{{- define "exitmesh.tlsSecretName" -}}
{{- if eq .Values.tls.mode "existingSecret" -}}{{ .Values.tls.existingSecret }}{{- else -}}{{ include "exitmesh.coordinatorName" . }}-tls{{- end -}}
{{- end -}}
{{- define "exitmesh.caConfigMapName" -}}{{ include "exitmesh.coordinatorName" . }}-ca{{- end -}}
{{- define "exitmesh.enrollmentSecretName" -}}
{{- if .Values.enrollment.existingSecret -}}{{ .Values.enrollment.existingSecret }}{{- else -}}{{ include "exitmesh.coordinatorName" . }}-enrollment{{- end -}}
{{- end -}}
{{- define "exitmesh.enrollmentSecretKey" -}}
{{- if .Values.enrollment.existingSecret -}}{{ .Values.enrollment.existingSecretKey }}{{- else -}}token{{- end -}}
{{- end -}}

{{- define "exitmesh.serviceHost" -}}
{{- printf "%s.%s.svc" (include "exitmesh.coordinatorName" .) .Values.namespaces.coordinator -}}
{{- end -}}

{{- define "exitmesh.serviceDNSNames" -}}
{{- $svc := include "exitmesh.coordinatorName" . -}}
{{- $ns := .Values.namespaces.coordinator -}}
{{- list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.%s" $svc $ns .Values.kubernetes.clusterDomain) | toJson -}}
{{- end -}}

{{- define "exitmesh.capabilityList" -}}
{{- $caps := list -}}
{{- if .Values.capabilities.inventory }}{{ $caps = append $caps "inventory" }}{{ end -}}
{{- if .Values.capabilities.metrics }}{{ $caps = append $caps "metrics" }}{{ end -}}
{{- if .Values.capabilities.logs }}{{ $caps = append $caps "logs" }}{{ end -}}
{{- toJson $caps -}}
{{- end -}}

{{- define "exitmesh.bundleDir" -}}
{{- if .Values.airgap.bundles.configMap -}}/etc/exitmesh/bundles{{- else -}}{{ .Values.airgap.bundles.imagePath }}{{- end -}}
{{- end -}}

{{- define "exitmesh.persistenceSize" -}}
{{- if .Values.airgap.enabled -}}{{ .Values.airgap.persistenceSize }}{{- else -}}{{ .Values.coordinator.persistence.size }}{{- end -}}
{{- end -}}

{{- define "exitmesh.spoolCapacity" -}}
{{- if .Values.airgap.enabled -}}{{ .Values.airgap.spoolCapacity }}{{- else -}}{{ .Values.coordinator.spool.capacity }}{{- end -}}
{{- end -}}

{{/* GOMEMLIMIT is the memory limit in MiB rendered as thousands of KiB, about 97.7 percent of the limit. */}}
{{- define "exitmesh.goMemLimitEnv" -}}
- name: EXITMESH_MEMORY_LIMIT_MIB
  valueFrom:
    resourceFieldRef:
      containerName: {{ .container }}
      resource: limits.memory
      divisor: 1Mi
- name: GOMEMLIMIT
  value: "$(EXITMESH_MEMORY_LIMIT_MIB)000KiB"
{{- end -}}

{{- define "exitmesh.restrictedContainerSecurityContext" -}}
allowPrivilegeEscalation: false
privileged: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: {{ .Values.node.uid }}
runAsGroup: {{ .Values.node.gid }}
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "exitmesh.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "exitmesh.nodeAPIPeerLabels" -}}
{{ include "exitmesh.selectorLabels" (dict "ctx" . "component" "node") }}
{{- end -}}

{{- define "exitmesh.config.kubernetes" -}}
kubernetes:
  scope: {{ .Values.kubernetes.scope }}
  customResources:
    {{- toYaml .Values.kubernetes.customResources | nindent 4 }}
  {{- with .Values.kubernetes.namespaces }}
  namespaces: {{ toJson . }}
  {{- end }}
  {{- with .Values.kubernetes.excludeNamespaces }}
  excludeNamespaces: {{ toJson . }}
  {{- end }}
  {{- with .Values.kubernetes.labelAllowlist }}
  labelAllowlist: {{ toJson . }}
  {{- end }}
  {{- with .Values.kubernetes.annotationAllowlist }}
  annotationAllowlist: {{ toJson . }}
  {{- end }}
  {{- with .Values.kubernetes.resources }}
  resources: {{ toJson . }}
  {{- end }}
  {{- with .Values.kubernetes.clusterName }}
  clusterName: {{ . | quote }}
  {{- end }}
{{- end -}}
{{- define "exitmesh.config.common" -}}
capabilities: {{ include "exitmesh.capabilityList" . }}
trust:
  roots: {{ toJson .Values.trust.roots }}
  {{- with .Values.trust.threshold }}
  threshold: {{ . }}
  {{- end }}
{{- with .Values.policy }}
policy:
  {{- toYaml . | nindent 2 }}
{{- end }}
logging:
  level: {{ .Values.logging.level | quote }}
  format: {{ .Values.logging.format | quote }}
{{- end -}}
{{- define "exitmesh.np.egressRule" -}}
- ports:
    {{- range .ports }}
    - protocol: TCP
      port: {{ . }}
    {{- end }}
  {{- with .cidrs }}
  to:
    {{- range . }}
    - ipBlock:
        cidr: {{ . }}
    {{- end }}
  {{- end }}
{{- end -}}
