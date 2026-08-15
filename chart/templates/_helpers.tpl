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

{{- define "mc.allowedFQDNEntries" -}}
- matchName: "curseforge.com"
- matchPattern: "*.curseforge.com"
- matchName: "edge.forgecdn.net"
- matchName: "mediafilez.forgecdn.net"
- matchName: "launchermeta.mojang.com"
- matchName: "piston-meta.mojang.com"
- matchName: "piston-data.mojang.com"
- matchName: "resources.download.minecraft.net"
- matchName: "libraries.minecraft.net"
- matchName: "maven.minecraftforge.net"
- matchName: "files.minecraftforge.net"
- matchName: "maven.creeperhost.net"
- matchName: "maven.fabricmc.net"
- matchName: "meta.fabricmc.net"
- matchName: "maven.neoforged.net"
- matchName: "sessionserver.mojang.com"
- matchName: "api.minecraftservices.com"
{{- range .Values.networkPolicy.extraAllowedFQDNs }}
- matchName: {{ . | quote }}
{{- end }}
{{- end -}}