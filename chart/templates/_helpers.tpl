{{- define "mc.labels" -}}
app.kubernetes.io/name: minecraft
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "mc.selectorLabels" -}}
app.kubernetes.io/name: minecraft
{{- end -}}

{{- define "playit.labels" -}}
app.kubernetes.io/name: playit
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "playit.selectorLabels" -}}
app.kubernetes.io/name: playit
{{- end -}}