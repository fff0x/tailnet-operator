{{- define "tailnet-operator.name" -}}
{{- default .Chart.Name .Values.fullnameOverride | trunc 53 | trimSuffix "-" -}}
{{- end -}}
{{- define "tailnet-operator.namespace" -}}
{{- default .Release.Namespace .Values.namespace -}}
{{- end -}}
{{- define "tailnet-operator.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}
{{- define "tailnet-operator.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name | quote }}
{{- end -}}
{{- define "tailnet-operator.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}
{{- define "tailnet-operator.agentImage" -}}
{{- $a := .Values.agentImage -}}
{{- if not (or $a.repository $a.tag $a.digest) -}}
{{- include "tailnet-operator.image" . -}}
{{- else -}}
{{- $repo := default .Values.image.repository $a.repository -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if $a.repository -}}{{- $tag = .Chart.AppVersion -}}{{- end -}}
{{- if $a.digest -}}
{{- printf "%s@%s" $repo $a.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (default $tag $a.tag) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- define "tailnet-operator.validate" -}}
{{- if lt (int .Values.replicas) 1 -}}{{- fail "replicas must be at least 1" -}}{{- end -}}
{{- if and (gt (int .Values.replicas) 1) (not .Values.leaderElection.enabled) -}}
{{- fail "replicas > 1 requires leaderElection.enabled=true" -}}
{{- end -}}
{{- range .Values.env.extra -}}
{{- if has .name (list "POD_NAMESPACE" "OPERATOR_IMAGE" "AGENT_IMAGE_PULL_SECRETS" "AGENT_RESOURCES" "SSL_CERT_FILE") -}}
{{- fail (printf "env.extra cannot override reserved variable %s" .name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
