# encrok

Minimal self-hosted reverse HTTP tunnel (ngrok-lite) — eine einzige Rust-Binary.

`A` läuft öffentlich und nimmt Tunnel entgegen, `B` (hinter jeder NAT/Firewall)
verbindet sich ausgehend per WebSocket und stellt lokale Ports unter einer
öffentlichen URL bereit. Alles streamend (Request-Body, Response-Body, chunked
Transfer-Encoding); Header und Bodies werden unverändert durchgereicht, A
injiziert `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` und
`X-Forwarded-From: encrok:<key-fingerprint>`.

## Build

```
encrok --proxy  --key <secret> [--listen 0.0.0.0:3000] [config.yaml]
encrok --client --server wss://TAG.deploy.zeugs.online/_endpoint --key <secret> \
       --local-port 3000 [--mapping /prefix:3049 ...] [config.yaml]
```

* `--proxy` (A): HTTP auf `--listen`, Tunnel-WebSocket auf `--ws-listen`
  (Default: listen-Port + 1). `/health` → `/_health`.
* `--client` (B): verbindet sich zu A (`Authorization`-Header = Pre-Shared-Key),
  leitet Requests per Longest-Prefix-Match an lokale TCP-Ports weiter
  (`--local-port` = Catch-all). Der Pfad wird unverändert weitergereicht.
* Config-Datei (YAML) + Flags (Flags gewinnen), `--help` zeigt alles.

## Installieren

```
curl -fsSL https://encrok.deploy.zeugs.online/install.sh | sh
# als systemd-service (client-Beispiel):
curl -fsSL https://encrok.deploy.zeugs.online/install.sh | sh -s -- \
  --client --server wss://meintag.deploy.zeugs.online/_endpoint \
  --key GEHEIM --local-port 3000 --service
```

## Docker (A)

Image `ghcr.io/danielmattertum/encrok:latest` (Alpine/scratch-basiert, statisch).
Nur den Key als Env übergeben:

```
docker run -d -e ENCROK_KEY=*** -p 127.0.0.1:3000:3000 -p 127.0.0.1:3001:3001 \
  ghcr.io/danielmattertum/encrok:latest
```

Auf dem a40-deploy-Service läuft das als `container_image: "encrok"`: ein Zip mit

```json
{ "name": "encrok-A", "container_image": "encrok",
  "container_env": { "ENCROK_KEY": "GEHEIM" } }
```

bei `POST /deploy` hochladen — der Deploy-Service routet `TAG.deploy.zeugs.online`
(HTTP **und** WebSocket) auf den Container. HTTP → Port 3000, `/_endpoint`-WebSocket → 3001.

## Protokoll (kurz)

1. B öffnet eine persistente WebSocket-Verbindung zu `A:ws-listen/_endpoint`
   (Header `Authorization: <key>`), meldet `hello <hostlabel>` als Textframe.
2. Requests auf A werden mit hyper http1 serialisiert und als Frames
   `[u32 stream_id][u8 flags][payload]` über den Control-Socket multiplexed.
3. B verbindet den passenden lokalen Port und pumpt Rohbytes in beide
   Richtungen mit; Response-Bytes fließen sofort zurück.
4. Client-Abbruch → CLOSE-Frame → B kappt die lokale Verbindung hart.

## Hinweise

* A führt keine TLS-Terminierung — es hinter einem HTTPS-Proxy laufen (Genau so
  macht es deploy.zeugs.online: TLS am Edge, WebSocket-Middleware → Port 3001).
* Ein Key = ein aktiver Tunnel (409 bei Doppelverbindung).
* `--host` ist nur relevant, wenn ein A mehrere Tunnel bedient (Hostlabel-Auswahl).
* WebSocket-Upgrades im getunnelten HTTP-Verkehr werden nicht unterstützt (nur HTTP/1).
