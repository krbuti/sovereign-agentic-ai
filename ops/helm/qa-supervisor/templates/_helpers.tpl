{{- define "qa.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "qa.fullname" -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "qa.labels" -}}
app.kubernetes.io/name: {{ include "qa.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
data-residency: eu
{{- end -}}
{{- define "qa.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qa.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "qa.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{- fail "image.digest is required: deploy signed images by digest, never by mutable tag" -}}
{{- end -}}
{{- end -}}
