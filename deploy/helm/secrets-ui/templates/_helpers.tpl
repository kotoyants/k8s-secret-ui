{{- define "secrets-ui.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "secrets-ui.fullname" -}}
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

{{- define "secrets-ui.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "secrets-ui.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "secrets-ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secrets-ui.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "secrets-ui.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "secrets-ui.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Fails rendering early with clear messages for missing required values. */}}
{{- define "secrets-ui.validate" -}}
{{- $_ := required "config.baseURL is required (e.g. https://secrets.example.com)" .Values.config.baseURL }}
{{- $_ := required "existingSecret is required (Secret with DATABASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SESSION_SECRET)" .Values.existingSecret }}
{{- if not .Values.config.allowedNamespaces }}
{{- fail "config.allowedNamespaces must list at least one namespace" }}
{{- end }}
{{- range .Values.config.allowedNamespaces }}
{{- if eq . "*" }}{{ fail "config.allowedNamespaces must not contain a wildcard" }}{{ end }}
{{- end }}
{{- end }}
