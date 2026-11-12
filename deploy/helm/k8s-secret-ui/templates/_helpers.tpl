{{- define "k8s-secret-ui.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "k8s-secret-ui.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "k8s-secret-ui.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "k8s-secret-ui.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "k8s-secret-ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "k8s-secret-ui.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "k8s-secret-ui.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "k8s-secret-ui.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Fails rendering early with clear messages for missing required values. */}}
{{- define "k8s-secret-ui.validate" -}}
{{- $_ := required "config.baseURL is required (e.g. https://secrets.example.com)" .Values.config.baseURL }}
{{- $_ := required "existingSecret is required (Secret with DATABASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SESSION_SECRET)" .Values.existingSecret }}
{{- if not .Values.config.allowedNamespaces }}
{{- fail "config.allowedNamespaces must list at least one namespace" }}
{{- end }}
{{- range .Values.config.allowedNamespaces }}
{{- if eq . "*" }}{{ fail "config.allowedNamespaces must not contain a wildcard" }}{{ end }}
{{- end }}
{{- end }}
