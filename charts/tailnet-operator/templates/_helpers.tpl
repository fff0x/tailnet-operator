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
{{- define "tailnet-operator.consoleLabels" -}}
app.kubernetes.io/name: tailnet-console
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/component: console
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}
{{- define "tailnet-operator.validateConsole" -}}
{{- $c := .Values.console -}}
{{- range $v := list (list "console.url" $c.url) (list "console.oidc.issuer" $c.oidc.issuer) (list "console.oidc.clientID" $c.oidc.clientID) (list "console.oidc.clientSecretRef.name" $c.oidc.clientSecretRef.name) (list "console.oidc.adminGroup" $c.oidc.adminGroup) -}}
{{- if not (index $v 1) -}}{{- fail (printf "%s is required when console.enabled=true" (index $v 0)) -}}{{- end -}}
{{- end -}}
{{- if not (hasPrefix "https://" $c.url) -}}{{- fail "console.url must start with https://" -}}{{- end -}}
{{- if not (hasPrefix "https://" $c.oidc.issuer) -}}{{- fail "console.oidc.issuer must start with https://" -}}{{- end -}}
{{- end -}}
{{- /*
ciliumEndpoints translates NetworkPolicyPeer entries into Cilium endpoint selectors so the
kubernetes and cilium providers share the same peer values. Namespace labels become
k8s:io.cilium.k8s.namespace.labels.<key>; an empty namespaceSelector means any namespace;
no namespaceSelector keeps Cilium's default scope (the policy namespace). ipBlock has no
identity in Cilium and is rejected.
*/ -}}
{{- define "tailnet-operator.ciliumEndpoints" -}}
{{- range . }}
{{- if .ipBlock }}{{ fail "networkPolicy.provider cilium cannot translate ipBlock peers; use namespaceSelector/podSelector" }}{{ end }}
{{- $labels := dict }}
{{- $exprs := list }}
{{- with .podSelector }}
{{- range $k, $v := .matchLabels }}{{ $_ := set $labels $k $v }}{{ end }}
{{- range .matchExpressions }}{{ $exprs = append $exprs . }}{{ end }}
{{- end }}
{{- if hasKey . "namespaceSelector" }}
{{- $ns := .namespaceSelector | default dict }}
{{- if and (not $ns.matchLabels) (not $ns.matchExpressions) }}
{{- $exprs = append $exprs (dict "key" "k8s:io.kubernetes.pod.namespace" "operator" "Exists") }}
{{- end }}
{{- range $k, $v := $ns.matchLabels }}{{ $_ := set $labels (printf "k8s:io.cilium.k8s.namespace.labels.%s" $k) $v }}{{ end }}
{{- range $ns.matchExpressions }}{{ $exprs = append $exprs (merge (dict "key" (printf "k8s:io.cilium.k8s.namespace.labels.%s" .key)) .) }}{{ end }}
{{- end }}
- matchLabels: {{ $labels | toJson }}
{{- with $exprs }}
  matchExpressions: {{ . | toJson }}
{{- end }}
{{- end }}
{{- end -}}
