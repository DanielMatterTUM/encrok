// encrok — minimal self-hosted reverse HTTP tunnel (ngrok-lite).
//
// One binary, two roles:
//   encrok --proxy --key <secret> [--listen 0.0.0.0:3000]         (A, public side)
//   encrok --client --server wss://host/_endpoint --key <secret> \
//          --local-port 1234 [--mapping /prefix:3049 ...]         (B, tunnel side)
//   encrok configfile.yaml   (same options as YAML, flags win)
//
// Wire protocol: one persistent WebSocket (control) from B to A at /_endpoint,
// authorized with a pre-shared key in the Authorization header. Requests arriving
// at A are serialized (hyper http1) as raw bytes, multiplexed over the control
// socket in binary frames [u32 stream_id][u8 flags][payload] and streamed to B.
// B pipes the bytes to a local TCP port and streams the response straight back.
// Fully streaming, both directions.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes as HBytes, Incoming};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as HsRequest, Response as HsResponse,
};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async_with_config, connect_async_with_config};

const ENDPOINT: &str = "/_endpoint";
const FIN: u8 = 1;
const CLOSE_F: u8 = 2;
const PING_INTERVAL: Duration = Duration::from_secs(25);
const RESP_HEAD_TIMEOUT: Duration = Duration::from_secs(120);
const CHUNK: usize = 64 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type AResult<T = ()> = Result<T, BoxError>;
type ResBody = BoxBody<HBytes, BoxError>;

// ---------------------------------------------------------------- utilities

/// Stable short fingerprint of a key (FNV-1a), for the X-Forwarded-From header
/// without leaking the secret itself.
fn key_tag(key: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("{:016x}", h)
}

fn frame(id: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + payload.len());
    v.put_u32(id);
    v.push(flags);
    v.extend_from_slice(payload);
    v
}

fn decode_frame(b: &[u8]) -> (u32, u8, &[u8]) {
    if b.len() < 5 {
        return (0, CLOSE_F, &[]);
    }
    let id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    (id, b[4], &b[5..])
}

fn plain(code: StatusCode, msg: &str) -> Response<ResBody> {
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(BodyExt::boxed(Full::new(HBytes::from(msg.to_string())).map_err(Into::<BoxError>::into)))
        .expect("static response")
}

fn ws_cfg() -> WebSocketConfig {
    let mut cfg = WebSocketConfig::default();
    cfg.max_message_size = Some(8 * CHUNK);
    cfg.max_frame_size = Some(8 * CHUNK);
    cfg
}

fn next_stream_id() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(2, Ordering::Relaxed);
    let salt = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u32)
        .unwrap_or(0))
        << 1;
    (n ^ salt) | 1
}

// ---------------------------------------------------------------- CLI / config

#[derive(Default, Deserialize)]
struct FileConfig {
    mode: Option<String>,
    listen: Option<String>,
    ws_listen: Option<String>,
    key: Option<String>,
    keys: Option<Vec<String>>,
    server: Option<String>,
    local_port: Option<u16>,
    mappings: Option<Vec<MappingYaml>>,
    host: Option<String>,
    tls_insecure: Option<bool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MappingYaml {
    Str(String),
    Map(HashMap<String, u16>),
}

struct Mapping {
    prefix: String, // "" matches everything
    port: u16,
}

impl Mapping {
    fn parse(spec: &str) -> Result<Mapping, String> {
        let (prefix, port) = spec
            .rsplit_once(':')
            .ok_or_else(|| format!("mapping '{spec}' muss '<prefix>:<port>' sein"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("mapping '{spec}': ungültige Port-Nummer"))?;
        if !prefix.is_empty() && !prefix.starts_with('/') {
            return Err(format!(
                "mapping '{spec}': Prefix muss mit '/' beginnen (oder leer sein)"
            ));
        }
        Ok(Mapping {
            prefix: prefix.to_string(),
            port,
        })
    }
}

#[derive(PartialEq)]
enum Mode {
    Proxy,
    Client,
}

struct Args {
    mode: Mode,
    listen: String,
    ws_listen: String,
    server: String,
    keys: Vec<String>,
    mappings: Vec<Mapping>,
    host: Option<String>,
    tls_insecure: bool,
}

const HELP: &str = "\
encrok — minimal reverse HTTP tunnel (ngrok-lite)

USAGE:
  encrok --proxy  --key <secret> [--key <secret>...] [--listen 0.0.0.0:3000] [config.yaml]
  encrok --client --server <url> --key <secret> --local-port <port>
                [--mapping /prefix:port]... [--host <announce>] [config.yaml]

Roles:
  --proxy   Public endpoint (A). Serves HTTP, accepts client tunnels at <url>/_endpoint.
  --client  Tunnel side (B). Connects to A and exposes local TCP port(s).

Options:
  --listen <addr:port>    A: HTTP listen address (default 0.0.0.0:3000, env ENCROK_PORT sets port)
  --ws-listen <addr:port> A: WebSocket listen address for tunnels (default: --listen port + 1)
  --server  <url>         B: wss://<host>/_endpoint of the proxy
  --key     <secret>      pre-shared Authorization key (repeatable on --proxy)
  --local-port <port>     B: catch-all mapping of every request path to this port
  --mapping <prefix:port> B: path-prefix -> port mapping (repeatable, first match wins;
                          the matched prefix is stripped before forwarding to the port,
                          path is forwarded to the backend unchanged)
  --tls-insecure          B: TLS-Zertifikate nicht prüfen (Gateways ohne volle Kette)
  --host <name>           B: host label this tunnel answers for (default: first label
                          of --server). Only used when the proxy serves several tunnels.
  -h, --help              this help

Config file (positional YAML, flags override):
  mode: proxy|client
  listen: 0.0.0.0:3000
  key: secret            (or keys: [a, b] on the proxy)
  server: wss://host/_endpoint
  local_port: 3000
  mappings: ['/prefix:3049', '/other:3032']   (or {'/prefix': 3049})
  host: mylabel

Env: ENCROK_KEY, ENCROK_PORT, ENCROK_SERVER
";

fn parse_args() -> Result<Args, String> {
    let mut mode: Option<Mode> = None;
    let mut listen: Option<String> = None;
    let mut ws_listen: Option<String> = None;
    let mut server: Option<String> = None;
    let mut keys: Vec<String> = Vec::new();
    let mut mappings: Vec<Mapping> = Vec::new();
    let mut host: Option<String> = None;
    let mut tls_insecure = false;
    let mut config_file: Option<String> = None;

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0usize;
    while i < argv.len() {
        let need_val = |name: &str, i: &mut usize| -> Result<String, String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| format!("{name} braucht einen Wert"))
        };
        match argv[i].as_str() {
            "--proxy" => mode = Some(Mode::Proxy),
            "--client" => mode = Some(Mode::Client),
            "--listen" => listen = Some(need_val("--listen", &mut i)?),
            "--ws-listen" => ws_listen = Some(need_val("--ws-listen", &mut i)?),
            "--server" => server = Some(need_val("--server", &mut i)?),
            "--key" => keys.push(need_val("--key", &mut i)?),
            "--local-port" => {
                let p: u16 = need_val("--local-port", &mut i)?
                    .parse()
                    .map_err(|_| "--local-port: Port-Nummer erwartet")?;
                mappings.push(Mapping {
                    prefix: String::new(),
                    port: p,
                });
            }
            "--mapping" => {
                let s = need_val("--mapping", &mut i)?;
                mappings.push(Mapping::parse(&s)?);
            }
            "--host" => host = Some(need_val("--host", &mut i)?),
            "--tls-insecure" => tls_insecure = true,
            "-h" | "--help" | "help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            s if s.starts_with('-') => return Err(format!("unbekannte Option '{s}' (--help)")),
            p => {
                if config_file.is_some() {
                    return Err("nur eine Config-Datei erlaubt".into());
                }
                config_file = Some(p.to_string());
            }
        }
        i += 1;
    }

    if let Some(path) = &config_file {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("Config-Datei {path}: {e}"))?;
        let cfg: FileConfig =
            serde_yaml::from_str(&raw).map_err(|e| format!("Config-Datei {path}: {e}"))?;
        if mode.is_none() {
            mode = match cfg.mode.as_deref() {
                Some("proxy") => Some(Mode::Proxy),
                Some("client") => Some(Mode::Client),
                Some(other) => {
                    return Err(format!("Config: mode '{other}' (erlaubt: proxy|client)"))
                }
                None => None,
            };
        }
        if listen.is_none() {
            listen = cfg.listen;
        }
        if ws_listen.is_none() {
            ws_listen = cfg.ws_listen;
        }
        if server.is_none() {
            server = cfg.server;
        }
        if keys.is_empty() {
            if let Some(ks) = cfg.keys {
                keys = ks;
            } else if let Some(k) = cfg.key {
                keys.push(k);
            }
        }
        if mappings.is_empty() {
            let mut ms = Vec::new();
            for m in cfg.mappings.unwrap_or_default() {
                match m {
                    MappingYaml::Str(s) => ms.push(Mapping::parse(&s)?),
                    MappingYaml::Map(map) => {
                        for (p, port) in map {
                            if !p.is_empty() && !p.starts_with('/') {
                                return Err(format!(
                                    "mappings: Prefix '{p}' muss mit '/' beginnen"
                                ));
                            }
                            ms.push(Mapping { prefix: p, port });
                        }
                    }
                }
            }
            if let Some(p) = cfg.local_port {
                ms.push(Mapping {
                    prefix: String::new(),
                    port: p,
                });
            }
            mappings = ms;
        }
        if host.is_none() {
            host = cfg.host;
        }
        tls_insecure |= cfg.tls_insecure.unwrap_or(false);
    }

    let mode = mode
        .ok_or("kein Modus: --proxy oder --client (oder mode: in der Config) — --help")?;

    let default_listen = match std::env::var("ENCROK_PORT") {
        Ok(p) if p.parse::<u16>().is_ok() => format!("0.0.0.0:{p}"),
        _ => "0.0.0.0:3000".to_string(),
    };
    let listen = listen.unwrap_or(default_listen);

    if keys.is_empty() {
        if let Ok(k) = std::env::var("ENCROK_KEY") {
            if !k.is_empty() {
                keys.push(k);
            }
        }
    }
    if keys.is_empty() {
        return Err("mindestens ein --key nötig (oder ENCROK_KEY / key: in der Config)".into());
    }

    // longest prefix first; empty prefix is the catch-all
    mappings.sort_by_key(|m| std::cmp::Reverse(m.prefix.len()));
    if mode == Mode::Client && mappings.is_empty() {
        return Err("--client braucht --local-port oder --mapping (oder local_port/mappings)".into());
    }

    let mut server = server.unwrap_or_default();
    if mode == Mode::Client && server.is_empty() {
        server = std::env::var("ENCROK_SERVER").unwrap_or_default();
    }
    if mode == Mode::Client && server.is_empty() {
        return Err("--client braucht --server <url> (oder server: in der Config)".into());
    }
    let server = normalize_url(&server);
    if host.is_none() && !server.is_empty() {
        host = server_host(&server)
            .map(|h| h.split('.').next().unwrap_or("").to_string());
    }

    let ws_listen = ws_listen.unwrap_or_else(|| bump_port(&listen));

    Ok(Args {
        mode,
        listen,
        ws_listen,
        server,
        keys,
        mappings,
        host,
        tls_insecure,
    })
}

fn normalize_url(s: &str) -> String {
    let s = s.trim();
    let (scheme, rest) = match s.split_once("://") {
        Some((sc, r)) => (sc.to_lowercase(), r.to_string()),
        None => ("wss".to_string(), s.to_string()),
    };
    let scheme = match scheme.as_str() {
        "http" => "ws",
        "https" => "wss",
        other => other,
    }
    .to_string();
    let (hostpart, path) = match rest.find('/') {
        Some(k) => (&rest[..k], rest[k..].to_string()),
        None => (rest.as_str(), String::new()),
    };
    let path = if path.is_empty() || path == "/" {
        ENDPOINT.to_string()
    } else {
        path
    };
    format!("{scheme}://{hostpart}{path}")
}

/// Same address with port + 1 (for the default WebSocket listener).
fn bump_port(listen: &str) -> String {
    match listen.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(p) => format!("{host}:{}", p.saturating_add(1)),
            Err(_) => listen.to_string(),
        },
        None => listen.to_string(),
    }
}

fn server_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    Some(rest.split('/').next().unwrap_or("").to_string())
}

// ---------------------------------------------------------------- shared types

#[derive(Clone)]
enum Evt {
    Data(Bytes, bool), // payload, fin
    Reset,
}

type Streams = Arc<StdMutex<HashMap<u32, mpsc::UnboundedSender<Evt>>>>;

// ---------------------------------------------------------------- proxy (A)

struct Tunnel {
    out: mpsc::UnboundedSender<Message>,
    streams: Streams,
    announced_host: StdMutex<Option<String>>,
    tag: String, // key fingerprint
}

struct ProxyState {
    keys: Vec<String>,
    tunnels: StdMutex<HashMap<String, Arc<Tunnel>>>, // pre-shared key -> tunnel
}

async fn proxy_main(args: &Args) -> AResult {
    let listener = TcpListener::bind(&args.listen)
        .await
        .map_err(|e| format!("bind {}: {e}", args.listen))?;
    let ws_listener = TcpListener::bind(&args.ws_listen)
        .await
        .map_err(|e| format!("bind {}: {e}", args.ws_listen))?;
    let state = Arc::new(ProxyState {
        keys: args.keys.clone(),
        tunnels: StdMutex::new(HashMap::new()),
    });
    eprintln!(
        "encrok proxy: HTTP auf {}, Tunnel-WebSocket auf {} ({} Key(s), Endpoint {ENDPOINT})",
        args.listen,
        args.ws_listen,
        args.keys.len()
    );
    {
        let state2 = state.clone();
        tokio::spawn(async move {
            if let Err(e) = ws_accept_loop(ws_listener, state2).await {
                eprintln!("encrok proxy: WebSocket-Listener: {e}");
            }
        });
    }
    loop {
        let (tcp, peer) = listener.accept().await.map_err(|e| format!("accept: {e}"))?;
        let io = TokioIo::new(tcp);
        let state2 = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                handle(req, peer, state2.clone())
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, svc)
                .await;
        });
    }
}

fn pick_tunnel(state: &ProxyState, host_hdr: &str) -> Option<Arc<Tunnel>> {
    let t = state.tunnels.lock().unwrap();
    let mut vals: Vec<Arc<Tunnel>> = t.values().cloned().collect();
    if vals.is_empty() {
        return None;
    }
    if vals.len() == 1 {
        return Some(vals.remove(0));
    }
    let label = host_hdr
        .split(':')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    vals.sort_by_key(|v| v.tag.clone());
    vals.into_iter()
        .find(|v| v.announced_host.lock().unwrap().as_deref() == Some(label))
}

async fn handle(
    mut req: Request<Incoming>,
    peer: SocketAddr,
    state: Arc<ProxyState>,
) -> Result<Response<ResBody>, hyper::Error> {
    let path = req.uri().path().to_string();
    if path == ENDPOINT {
        return Ok(plain(
            StatusCode::BAD_REQUEST,
            "encrok: tunnel endpoint speaks WebSocket on the ws-listen port",
        ));
    }
    if path == "/_health" && req.method() == Method::GET {
        let n = state.tunnels.lock().unwrap().len();
        return Ok(plain(
            StatusCode::OK,
            &format!("encrok proxy up — {n} tunnel(s) connected\n"),
        ));
    }

    let host_hdr = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Some(tunnel) = pick_tunnel(&state, &host_hdr) else {
        return Ok(plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "encrok: no tunnel connected for this host",
        ));
    };

    inject_forwarded(&mut req, peer, &tunnel.tag);

    match serve_via_tunnel(req, tunnel).await {
        Ok(r) => Ok(r),
        Err(e) => {
            eprintln!("encrok proxy: upstream error: {e}");
            Ok(plain(
                StatusCode::BAD_GATEWAY,
                "encrok: tunnel/backend error",
            ))
        }
    }
}

fn inject_forwarded(req: &mut Request<Incoming>, peer: SocketAddr, tag: &str) {
    let headers = req.headers_mut();
    let xff_key = HeaderName::from_static("x-forwarded-for");
    let existing = headers
        .get(&xff_key)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let ip = peer.ip().to_string();
    let joined = match existing {
        Some(s) if !s.is_empty() => format!("{s}, {ip}"),
        _ => ip,
    };
    if let Ok(v) = HeaderValue::from_str(&joined) {
        headers.insert(xff_key, v);
    }
    if let Some(h) = headers.get(header::HOST).cloned() {
        headers.insert(HeaderName::from_static("x-forwarded-host"), h);
    }
    let proto = headers
        .get(HeaderName::from_static("x-forwarded-proto"))
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("http"));
    headers.insert(HeaderName::from_static("x-forwarded-proto"), proto);
    if let Ok(v) = HeaderValue::from_str(&format!("encrok:{tag}")) {
        headers.insert(HeaderName::from_static("x-forwarded-from"), v);
    }
}

/// Multiplexed byte stream for one tunnel stream id; presents AsyncRead+AsyncWrite
/// so hyper's http1 client can speak HTTP/1 through the multiplexed control socket.
struct TunnelStream {
    id: u32,
    rx: mpsc::UnboundedReceiver<Evt>,
    out: mpsc::UnboundedSender<Message>,
    streams: Streams,
    pending: Option<(Bytes, usize, bool)>, // bytes, consumed, had_fin
    fin_sent: bool,
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        if !self.fin_sent {
            let _ = self.out.send(Message::binary(frame(self.id, CLOSE_F, &[])));
        }
        self.streams.lock().unwrap().remove(&self.id);
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some((bytes, consumed, fin)) = &mut self.pending {
                let avail = bytes.len() - *consumed;
                if avail > 0 {
                    let n = avail.min(buf.remaining());
                    buf.put_slice(&bytes[*consumed..*consumed + n]);
                    *consumed += n;
                    return Poll::Ready(Ok(()));
                }
                let fin = *fin;
                self.pending = None;
                if !fin {
                    continue; // more frames expected
                }
                return Poll::Ready(Ok(())); // clean EOF
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(Evt::Data(b, fin))) => {
                    if b.is_empty() {
                        if fin {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        continue;
                    }
                    self.pending = Some((b, 0, fin));
                }
                Poll::Ready(Some(Evt::Reset)) => return Poll::Ready(Ok(())), // truncating EOF
                Poll::Ready(None) => return Poll::Ready(Ok(())),             // control died
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fin_sent {
            return Poll::Ready(Err(io::Error::other("tunnel stream finished")));
        }
        self.out
            .send(Message::binary(frame(self.id, 0, buf)))
            .map_err(|_| io::Error::other("tunnel closed"))?;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.fin_sent {
            self.as_mut().get_mut().fin_sent = true;
            let _ = self.out.send(Message::binary(frame(self.id, FIN, &[])));
        }
        Poll::Ready(Ok(()))
    }
}

/// Response body wrapper: the hyper client connection (and with it the tunnel
/// stream) is only released after the body has fully streamed or been dropped,
/// so client cancels reach B as CLOSE frames.
struct TunnelBody<B> {
    inner: B,
    _guard: hyper::client::conn::http1::SendRequest<ResBody>,
}

impl<B: Body<Data = HBytes> + Unpin + 'static> Body for TunnelBody<B> {
    type Data = HBytes;
    type Error = B::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

async fn serve_via_tunnel(
    req: Request<Incoming>,
    tunnel: Arc<Tunnel>,
) -> AResult<Response<ResBody>> {
    let id = next_stream_id();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel();
    tunnel.streams.lock().unwrap().insert(id, evt_tx);

    let io = TokioIo::new(TunnelStream {
        id,
        rx: evt_rx,
        out: tunnel.out.clone(),
        streams: tunnel.streams.clone(),
        pending: None,
        fin_sent: false,
    });

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .title_case_headers(true)
        .handshake(io)
        .await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = req.map(|b| BodyExt::boxed(b.map_err(Into::<BoxError>::into)));
    let resp = tokio::time::timeout(RESP_HEAD_TIMEOUT, sender.send_request(req)).await??;

    let (parts, incoming) = resp.into_parts();
    let body = TunnelBody {
        inner: incoming,
        _guard: sender,
    };
    Ok(Response::from_parts(
        parts,
        BodyExt::boxed(body.map_err(Into::<BoxError>::into)),
    ))
}

async fn ws_accept_loop(listener: TcpListener, state: Arc<ProxyState>) -> AResult {
    loop {
        let (tcp, _peer) = listener.accept().await.map_err(|e| format!("ws accept: {e}"))?;
        let state2 = state.clone();
        tokio::spawn(async move {
            // Auth + path check happen inside the handshake callback; the matched
            // key is carried out through this cell.
            let matched: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
            let matched_cb = matched.clone();
            let state_cb = state2.clone();
            let cb = move |req: &HsRequest, resp: HsResponse| -> Result<HsResponse, ErrorResponse> {
                if req.uri().path() != ENDPOINT {
                    return Err(err_hs(StatusCode::NOT_FOUND, "encrok: unknown endpoint"));
                }
                let raw = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                // Accept the pre-shared key raw or in Bearer form.
                let auth = raw.strip_prefix("Bearer ").unwrap_or(&raw).trim();
                let key = match state_cb.keys.iter().find(|k| **k == auth) {
                    Some(k) => k.clone(),
                    None => {
                        return Err(err_hs(
                            StatusCode::UNAUTHORIZED,
                            "encrok: authorization key missing or wrong",
                        ))
                    }
                };
                if state_cb.tunnels.lock().unwrap().contains_key(&key) {
                    return Err(err_hs(
                        StatusCode::CONFLICT,
                        "encrok: a tunnel with this key is already connected",
                    ));
                }
                *matched_cb.lock().unwrap() = Some(key);
                Ok(resp)
            };
            let ws = match accept_hdr_async_with_config(tcp, cb, Some(ws_cfg())).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("encrok proxy: ws handshake abgelehnt: {e}");
                    return;
                }
            };
            let Some(key) = matched.lock().unwrap().take() else {
                return; // callback never registered (should not happen)
            };
            install_tunnel(ws, key, state2).await;
        });
    }
}

fn err_hs(code: StatusCode, msg: &str) -> ErrorResponse {
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Some(msg.to_string()))
        .expect("handshake error response")
}

/// Register a freshly accepted control connection as a tunnel and drive it
/// until the client disconnects.
async fn install_tunnel(
    ws: tokio_tungstenite::WebSocketStream<TcpStream>,
    key: String,
    state: Arc<ProxyState>,
) {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    let tunnel = Arc::new(Tunnel {
        out: out_tx,
        streams: Arc::new(StdMutex::new(HashMap::new())),
        announced_host: StdMutex::new(None),
        tag: key_tag(&key),
    });
    state.tunnels.lock().unwrap().insert(key.clone(), tunnel.clone());
    eprintln!("encrok proxy: tunnel connected (key …{})", &key_tag(&key)[..8]);

    let (mut sink, mut stream) = ws.split();
    // writer task
    tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });
    // keepalive pings
    {
        let out = tunnel.out.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(PING_INTERVAL);
            t.tick().await;
            loop {
                t.tick().await;
                if out.send(Message::Ping(Bytes::new())).is_err() {
                    break;
                }
            }
        });
    }
    // control read loop
    {
        let state2 = state.clone();
        let this = tunnel.clone();
        loop {
            match stream.next().await {
                Some(Ok(msg)) => match msg {
                    Message::Binary(b) => {
                        let (id, flags, payload) = decode_frame(&b);
                        let streams = this.streams.lock().unwrap();
                        if let Some(tx) = streams.get(&id) {
                            if flags & CLOSE_F != 0 {
                                let _ = tx.send(Evt::Reset);
                            } else {
                                let _ = tx.send(Evt::Data(
                                    Bytes::copy_from_slice(payload),
                                    flags & FIN != 0,
                                ));
                            }
                        }
                    }
                    Message::Text(t) => {
                        let t = t.as_str().trim();
                        if let Some(h) = t.strip_prefix("hello") {
                            *this.announced_host.lock().unwrap() = Some(h.trim().to_string());
                        }
                    }
                    Message::Close(_) => break,
                    _ => {} // Ping/Pong: answered by tungstenite automatically
                },
                _ => break,
            }
        }
        {
            let streams = this.streams.lock().unwrap();
            for tx in streams.values() {
                let _ = tx.send(Evt::Reset);
            }
        }
        let mut t = state2.tunnels.lock().unwrap();
        if let Some(cur) = t.get(&key) {
            if Arc::ptr_eq(cur, &this) {
                t.remove(&key);
            }
        }
        eprintln!("encrok proxy: tunnel dropped (key …{})", &key_tag(&key)[..8]);
    }
}

// ---------------------------------------------------------------- client (B)

async fn client_main(args: &Args) -> AResult {
    eprintln!(
        "encrok client: verbinde {} ({} mapping(s))",
        args.server,
        args.mappings.len()
    );
    loop {
        match client_once(args).await {
            Ok(()) => eprintln!("encrok client: verbindung geschlossen"),
            Err(e) => eprintln!("encrok client: fehler: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Debug)]
struct NoVerifier;
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end: &rustls::pki_types::CertificateDer<'_>,
        _ints: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
             ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ECDSA_NISTP521_SHA512,
             ED25519, ED448, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512]
    }
}

async fn client_once(args: &Args) -> AResult {
    let cfg = ws_cfg();
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut hs = args
        .server
        .parse::<hyper::Uri>()
        .map_err(|e| e.to_string())?
        .into_client_request()
        .map_err(|e| e.to_string())?;
    hs.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&args.keys[0]).map_err(|e| e.to_string())?,
    );
    let (ws, _resp) = if args.tls_insecure {
        use std::sync::Arc;
        use tokio_tungstenite::Connector;
        let cc = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
        tokio_tungstenite::connect_async_tls_with_config(
            hs,
            Some(cfg),
            true,
            Some(Connector::Rustls(Arc::new(cc))),
        )
        .await?
    } else {
        connect_async_with_config(hs, Some(cfg), true).await?
    };
    eprintln!("encrok client: verbunden mit {}", args.server);

    let (mut sink, mut stream) = ws.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });
    if let Some(h) = &args.host {
        out_tx.send(Message::text(format!("hello {h}"))).ok();
    }
    {
        let out = out_tx.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(PING_INTERVAL);
            t.tick().await;
            loop {
                t.tick().await;
                if out.send(Message::Ping(Bytes::new())).is_err() {
                    break;
                }
            }
        });
    }

    let mut relays: HashMap<u32, mpsc::UnboundedSender<Evt>> = HashMap::new();

    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let Message::Binary(b) = msg else { continue };
        let (id, flags, payload) = decode_frame(&b);
        if flags & CLOSE_F != 0 {
            if let Some(tx) = relays.remove(&id) {
                let _ = tx.send(Evt::Reset);
            }
            continue;
        }
        let tx = match relays.get(&id) {
            Some(tx) => tx.clone(),
            None => {
                let (tx, rx) = mpsc::unbounded_channel();
                relays.insert(id, tx.clone());
                let out = out_tx.clone();
                let mapping = args
                    .mappings
                    .iter()
                    .find(|m| {
                        !m.prefix.is_empty() && head_matches_prefix(&m.prefix, &payload)
                    })
                    .or_else(|| args.mappings.iter().find(|m| m.prefix.is_empty()));
                let mapping = mapping.map(|m| (m.prefix.clone(), m.port));
                tokio::spawn(relay(id, rx, out, mapping));
                tx
            }
        };
        let _ = tx.send(Evt::Data(Bytes::copy_from_slice(payload), flags & FIN != 0));
        relays.retain(|_, tx| !tx.is_closed());
    }
    Ok(())
}

/// Prefix match against the raw HTTP request head: the first frame starts with
/// the request line "METHOD /path HTTP/1.1".
fn head_matches_prefix(prefix: &str, payload: &[u8]) -> bool {
    let head = &payload[..payload.len().min(8192)];
    let line_end = head.iter().position(|&c| c == b'\n').unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[..line_end]);
    line.split_whitespace()
        .nth(1)
        .is_some_and(|uri: &str| {
            uri.starts_with(prefix)
                && matches!(uri.as_bytes().get(prefix.len()), None | Some(b'/') | Some(b'?'))
        })
}

/// Rewrite the request line of the first frame: remove a matched path prefix,
/// so the local server sees paths relative to its mount point ("/coding/x" -> "/x").
fn strip_uri_prefix(payload: &[u8], prefix: &str) -> Vec<u8> {
    let Some(nl) = payload.iter().position(|&c| c == b'\n') else {
        return payload.to_vec();
    };
    let line = &payload[..nl];
    let mut parts = line.splitn(3, |&c| c == b' ');
    let (Some(method), Some(uri), Some(ver)) = (parts.next(), parts.next(), parts.next()) else {
        return payload.to_vec();
    };
    let keep: Vec<u8> = match uri.strip_prefix(prefix.as_bytes()) {
        Some(tail) if tail.is_empty() => b"/".to_vec(),
        Some(tail) if tail[0] == b'?' => {
            let mut v = b"/".to_vec();
            v.extend_from_slice(tail);
            v
        }
        Some(tail) if tail[0] == b'/' => tail.to_vec(),
        _ => return payload.to_vec(), // not a real prefix boundary: leave untouched
    };
    let keep = keep.as_slice();
    let mut out = Vec::with_capacity(payload.len());
    out.extend_from_slice(method);
    out.push(b' ');
    out.extend_from_slice(keep);
    out.push(b' ');
    out.extend_from_slice(ver.strip_suffix(&[b'\r'][..]).unwrap_or(ver));
    out.extend_from_slice(&payload[nl..]);
    out
}

/// One request stream: pump tunnel <-> local TCP port.
async fn relay(
    id: u32,
    mut rx: mpsc::UnboundedReceiver<Evt>,
    out: mpsc::UnboundedSender<Message>,
    mapping: Option<(String, u16)>,
) {
    let (mut strip_prefix, port) = match mapping {
        Some((p, port)) => (if p.is_empty() { None } else { Some(p) }, port),
        None => {
            let body = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = out.send(Message::binary(frame(id, FIN, body)));
            return;
        }
    };
    let tcp = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            eprintln!("encrok client: stream {id}: connect 127.0.0.1:{port}: {e}");
            let _ = out.send(Message::binary(frame(id, CLOSE_F, &[])));
            return;
        }
        Err(_) => {
            let _ = out.send(Message::binary(frame(id, CLOSE_F, &[])));
            return;
        }
    };
    let (mut read_half, mut write_half) = tcp.into_split();

    let mut remote_done = false;
    let mut buf = vec![0u8; CHUNK];
    loop {
        tokio::select! {
            biased;
            evt = rx.recv(), if !remote_done => {
                match evt {
                    Some(Evt::Data(mut bytes, fin)) => {
                        if let Some(prefix) = strip_prefix.take() {
                            bytes = Bytes::from(strip_uri_prefix(&bytes, &prefix));
                        }
                        if !bytes.is_empty() && write_half.write_all(&bytes).await.is_err() {
                            break;
                        }
                        if fin {
                            remote_done = true;
                            let _ = write_half.shutdown().await; // backend sees end of request
                        }
                    }
                    Some(Evt::Reset) | None => return, // client gone: hard cut
                }
            }
            n = read_half.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break, // response complete or error -> FIN
                    Ok(k) => {
                        if out.send(Message::binary(frame(id, 0, &buf[..k]))).is_err() {
                            return; // control died
                        }
                    }
                }
            }
        }
    }
    let _ = out.send(Message::binary(frame(id, FIN, &[])));
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("encrok: {e}");
            std::process::exit(2);
        }
    };
    let r = match args.mode {
        Mode::Proxy => proxy_main(&args).await,
        Mode::Client => client_main(&args).await,
    };
    if let Err(e) = r {
        eprintln!("encrok: {e}");
        std::process::exit(1);
    }
}
