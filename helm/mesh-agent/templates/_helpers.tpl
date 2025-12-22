{{/*
Expand the name of the chart.
*/}}
{{- define "mesh-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "mesh-agent.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "mesh-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "mesh-agent.labels" -}}
helm.sh/chart: {{ include "mesh-agent.chart" . }}
{{ include "mesh-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mesh-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mesh-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "mesh-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mesh-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Get the auth key secret name
*/}}
{{- define "mesh-agent.secretName" -}}
{{- if .Values.meshAgent.existingSecret.enabled }}
{{- .Values.meshAgent.existingSecret.name }}
{{- else }}
{{- include "mesh-agent.fullname" . }}-auth
{{- end }}
{{- end }}

{{/*
Build proxy arguments string
*/}}
{{- define "mesh-agent.proxyArgs" -}}
{{- $proxies := list }}
{{- range .Values.meshAgent.proxies }}
{{- $proxies = append $proxies (printf "%d:%s:%d" (int .localPort) .targetHost (int .targetPort)) }}
{{- end }}
{{- join "," $proxies }}
{{- end }}
