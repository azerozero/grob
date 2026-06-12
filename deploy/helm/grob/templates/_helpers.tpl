{{/*
Expand the name of the chart.
*/}}
{{- define "grob.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "grob.fullname" -}}
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
Chart name and version as used by the chart label.
*/}}
{{- define "grob.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "grob.labels" -}}
helm.sh/chart: {{ include "grob.chart" . }}
{{ include "grob.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "grob.selectorLabels" -}}
app.kubernetes.io/name: {{ include "grob.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "grob.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "grob.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret to inject (existing or chart-rendered).
*/}}
{{- define "grob.secretName" -}}
{{- if .Values.secret.existingSecret }}
{{- .Values.secret.existingSecret }}
{{- else }}
{{- printf "%s-secret" (include "grob.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Name of the PersistentVolumeClaim (existing or chart-rendered).
*/}}
{{- define "grob.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "grob.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Multi-replica budget guard. Fails the render when more than one replica is
requested without acknowledging the per-pod budget risk.
*/}}
{{- define "grob.budgetGuard" -}}
{{- $multi := or (gt (int .Values.replicaCount) 1) (and .Values.autoscaling.enabled (gt (int .Values.autoscaling.maxReplicas) 1)) -}}
{{- if and $multi (not .Values.budget.acknowledgeMultiReplicaRisk) -}}
{{- fail "grob: replicaCount>1 or autoscaling.maxReplicas>1 makes spend-budget enforcement PER-POD (per-pod spend journals on ReadWriteOnce storage), so the real budget becomes N× the configured cap and diverges between pods. Set budget.acknowledgeMultiReplicaRisk=true to proceed (ideally with a ReadWriteMany shared volume). See the chart README." -}}
{{- end -}}
{{- end -}}
