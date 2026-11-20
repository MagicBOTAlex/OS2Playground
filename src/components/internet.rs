//! The `internet` component: HTTP(S) requests performed on a background thread,
//! mirroring the OpenComputers internet card's streaming request handle.

use super::{arg_bytes, arg_string, multi1, Component, MethodInfo};
use mlua::{Lua, MultiValue, Value, Variadic};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// OpenComputers clamps every `read` call to this many bytes.
const MAX_READ_BUFFER: usize = 2048;

/// Upper bound for a TCP connect attempt (name resolution runs on the worker
/// thread as well, so a hung resolver never blocks the Lua machine).
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct HttpState {
    done: bool,
    error: Option<String>,
    response: Option<ResponseInfo>,
    body: Vec<u8>,
    pos: usize,
    closed: bool,
}

struct ResponseInfo {
    code: i32,
    message: String,
    headers: Vec<(String, Vec<String>)>,
}

enum TcpStatus {
    Connecting,
    Connected,
    Failed(String),
    Closed,
}

struct TcpState {
    status: TcpStatus,
    stream: Option<TcpStream>,
    eof: bool,
    id: String,
}

/// Process-wide counter for socket ids. OpenComputers uses a random UUID; the
/// only observable requirement is that ids are unique and stable per handle.
static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(1);

fn next_socket_id() -> String {
    let n = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    format!("ocplay-tcp-{:016x}", n)
}

/// The internet card. HTTP runs asynchronously so the machine keeps rendering
/// while a request is in flight, exactly like the real component.
pub struct Internet {
    pub enabled: bool,
    pub timeout: f64,
    pub user_agent: String,
    pub tcp_enabled: bool,
}

impl Internet {
    pub fn new(enabled: bool, timeout: f64, user_agent: String, tcp_enabled: bool) -> Internet {
        Internet {
            enabled,
            timeout,
            user_agent,
            tcp_enabled,
        }
    }

    fn connect(&self, lua: &Lua, args: &[Value]) -> mlua::Result<MultiValue> {
        let address = arg_string(args, 0)?;
        if !self.enabled {
            return err(lua, "internet access is unavailable");
        }
        if !self.tcp_enabled {
            return err(lua, "tcp connections are unavailable");
        }

        // `internet.socket` (OpenOS) passes the port embedded in the address,
        // while direct callers use the second argument. An embedded port wins
        // when both are present, matching OpenComputers' URI handling.
        let explicit_port = match args.get(1) {
            None | Some(Value::Nil) => None,
            Some(_) => Some(super::arg_int(args, 1)?),
        };
        let (host, port) = match parse_endpoint(&address, explicit_port) {
            Ok(endpoint) => endpoint,
            Err(reason) => return err(lua, &reason),
        };

        let state = Arc::new(Mutex::new(TcpState {
            status: TcpStatus::Connecting,
            stream: None,
            eof: false,
            id: next_socket_id(),
        }));
        let worker = state.clone();
        std::thread::spawn(move || {
            let outcome = connect_socket(&host, port);
            let mut state = worker.lock().unwrap();
            match outcome {
                Ok(stream) => {
                    if matches!(state.status, TcpStatus::Closed) {
                        // Closed while the connect was in flight: drop the
                        // stream so the connection is torn down immediately.
                        drop(stream);
                    } else if let Err(reason) = stream.set_nonblocking(true) {
                        state.status = TcpStatus::Failed(reason.to_string());
                    } else {
                        state.stream = Some(stream);
                        state.status = TcpStatus::Connected;
                    }
                }
                Err(reason) => {
                    if !matches!(state.status, TcpStatus::Closed) {
                        state.status = TcpStatus::Failed(reason);
                    }
                }
            }
        });

        let handle = lua.create_table()?;

        let finish_state = state.clone();
        handle.set(
            "finishConnect",
            lua.create_function(move |_lua, _: Variadic<Value>| {
                let state = finish_state.lock().unwrap();
                match &state.status {
                    TcpStatus::Connecting => Ok(multi1(Value::Boolean(false))),
                    TcpStatus::Connected => Ok(multi1(Value::Boolean(true))),
                    TcpStatus::Failed(reason) => Err(mlua::Error::RuntimeError(format!(
                        "connection failed: {}",
                        reason
                    ))),
                    TcpStatus::Closed => Ok(multi1(Value::Boolean(false))),
                }
            })?,
        )?;

        let read_state = state.clone();
        handle.set(
            "read",
            lua.create_function(move |lua, args: Variadic<Value>| {
                let args = skip_self(args.as_ref());
                let limit = match args.first() {
                    None | Some(Value::Nil) => MAX_READ_BUFFER,
                    Some(_) => super::arg_int(args, 0)?.max(0) as usize,
                }
                .min(MAX_READ_BUFFER);

                let mut state = read_state.lock().unwrap();
                match &state.status {
                    // Still connecting: an empty string tells the caller to retry.
                    TcpStatus::Connecting => {
                        return Ok(multi1(Value::String(lua.create_string("")?)))
                    }
                    TcpStatus::Failed(reason) => return err(lua, reason),
                    TcpStatus::Closed => return Ok(multi1(Value::Nil)),
                    TcpStatus::Connected => {}
                }
                if state.eof {
                    return Ok(multi1(Value::Nil));
                }
                if limit == 0 {
                    return Ok(multi1(Value::String(lua.create_string("")?)));
                }

                let mut buffer = vec![0u8; limit];
                let outcome = {
                    let stream = state.stream.as_mut().unwrap();
                    stream.read(&mut buffer)
                };
                match outcome {
                    Ok(0) => {
                        state.eof = true;
                        Ok(multi1(Value::Nil))
                    }
                    Ok(n) => {
                        buffer.truncate(n);
                        Ok(multi1(Value::String(lua.create_string(&buffer)?)))
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        Ok(multi1(Value::String(lua.create_string("")?)))
                    }
                    Err(error) => {
                        state.status = TcpStatus::Failed(error.to_string());
                        err(lua, &error.to_string())
                    }
                }
            })?,
        )?;

        let write_state = state.clone();
        handle.set(
            "write",
            lua.create_function(move |_lua, args: Variadic<Value>| {
                let args = skip_self(args.as_ref());
                let data = arg_bytes(args, 0)?;
                let mut state = write_state.lock().unwrap();
                if !matches!(state.status, TcpStatus::Connected) {
                    return Ok(multi1(Value::Integer(0)));
                }
                let outcome = {
                    let stream = state.stream.as_mut().unwrap();
                    stream.write(&data)
                };
                let written = match outcome {
                    Ok(n) => n,
                    // A full send buffer is normal for a non-blocking socket;
                    // the caller retries with the remaining bytes.
                    Err(error) if error.kind() == ErrorKind::WouldBlock => 0,
                    Err(_) => 0,
                };
                Ok(multi1(Value::Integer(written as i64)))
            })?,
        )?;

        let close_state = state.clone();
        handle.set(
            "close",
            lua.create_function(move |_, _: Variadic<Value>| {
                let mut state = close_state.lock().unwrap();
                if matches!(state.status, TcpStatus::Closed) {
                    return Ok(());
                }
                if let Some(stream) = state.stream.take() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                state.status = TcpStatus::Closed;
                state.eof = true;
                Ok(())
            })?,
        )?;

        let id_state = state.clone();
        handle.set(
            "id",
            lua.create_function(move |lua, _: Variadic<Value>| {
                let state = id_state.lock().unwrap();
                Ok(multi1(Value::String(lua.create_string(state.id.as_str())?)))
            })?,
        )?;

        Ok(multi1(Value::Table(handle)))
    }

    fn request(&self, lua: &Lua, args: &[Value]) -> mlua::Result<MultiValue> {
        let url = arg_string(args, 0)?;
        if !self.enabled {
            return err(lua, "internet access is unavailable");
        }
        if let Err(reason) = validate_url(&url) {
            return err(lua, &reason);
        }

        let post = match args.get(1) {
            Some(Value::String(s)) => Some(s.as_bytes().to_vec()),
            _ => None,
        };
        let headers = parse_headers(args.get(2))?;
        let method = match args.get(3) {
            Some(Value::String(s)) => Some(s.to_string_lossy().to_string()),
            _ => None,
        };

        let state = Arc::new(Mutex::new(HttpState::default()));
        let worker = state.clone();
        let timeout = self.timeout;
        let user_agent = self.user_agent.clone();
        let url_owned = url.clone();
        std::thread::spawn(move || {
            let outcome = perform_request(&url_owned, method, post, headers, timeout, &user_agent);
            let mut state = worker.lock().unwrap();
            state.done = true;
            match outcome {
                Ok((info, body)) => {
                    // OpenComputers never exposes the error stream: reading a
                    // response with a >= 400 status fails, but `response()`
                    // still reports the status code and headers.
                    if info.code >= 400 {
                        state.error = Some(format!("{} {}", info.code, info.message));
                    }
                    state.response = Some(info);
                    state.body = body;
                }
                Err(reason) => state.error = Some(reason),
            }
        });

        let handle = lua.create_table()?;

        let read_state = state.clone();
        handle.set(
            "read",
            lua.create_function(move |lua, n: Option<i64>| {
                let mut state = read_state.lock().unwrap();
                if let Some(reason) = &state.error {
                    return err(lua, reason);
                }
                if !state.done {
                    // Not ready yet: an empty string tells the caller to retry.
                    return Ok(multi1(Value::String(lua.create_string("")?)));
                }
                if state.pos >= state.body.len() {
                    return Ok(multi1(Value::Nil));
                }
                let limit = n.unwrap_or(i64::MAX).max(0) as usize;
                let limit = limit.min(MAX_READ_BUFFER);
                let end = (state.pos + limit).min(state.body.len());
                let chunk = state.body[state.pos..end].to_vec();
                state.pos = end;
                Ok(multi1(Value::String(lua.create_string(&chunk)?)))
            })?,
        )?;

        let response_state = state.clone();
        handle.set(
            "response",
            lua.create_function(move |lua, ()| {
                let state = response_state.lock().unwrap();
                let mut out = MultiValue::new();
                match &state.response {
                    Some(info) => {
                        out.push_back(Value::Integer(info.code as i64));
                        out.push_back(Value::String(lua.create_string(&info.message)?));
                        let table = lua.create_table()?;
                        for (name, values) in &info.headers {
                            let list = lua.create_table()?;
                            for (index, value) in values.iter().enumerate() {
                                list.set(index + 1, value.as_str())?;
                            }
                            table.set(name.as_str(), list)?;
                        }
                        out.push_back(Value::Table(table));
                    }
                    None => out.push_back(Value::Nil),
                }
                Ok(out)
            })?,
        )?;

        let finish_state = state.clone();
        handle.set(
            "finishConnect",
            lua.create_function(move |lua, ()| {
                let state = finish_state.lock().unwrap();
                if let Some(reason) = &state.error {
                    return err(lua, reason);
                }
                Ok(multi1(Value::Boolean(state.done)))
            })?,
        )?;

        handle.set(
            "close",
            lua.create_function(move |_, ()| {
                let mut state = state.lock().unwrap();
                state.closed = true;
                state.body.clear();
                Ok(())
            })?,
        )?;

        Ok(multi1(Value::Table(handle)))
    }
}

impl Component for Internet {
    fn type_name(&self) -> &'static str {
        "internet"
    }

    fn slot(&self) -> &'static str {
        "card"
    }

    fn methods(&self) -> &'static [MethodInfo] {
        METHODS
    }

    fn invoke(&self, lua: &Lua, method: &str, args: &[Value]) -> mlua::Result<MultiValue> {
        match method {
            "isHttpEnabled" => Ok(multi1(Value::Boolean(self.enabled))),
            "isTcpEnabled" => Ok(multi1(Value::Boolean(self.tcp_enabled))),
            "request" => self.request(lua, args),
            "connect" => self.connect(lua, args),
            _ => Err(mlua::Error::RuntimeError("no such method".into())),
        }
    }

    fn device_info(&self) -> Vec<(String, String)> {
        vec![
            ("class".into(), "card".into()),
            ("description".into(), "Internet Card".into()),
            ("vendor".into(), "MightyPirates GmbH & Co. KG".into()),
            ("product".into(), "Tier 2 Internet Card".into()),
        ]
    }
}

const METHODS: &[MethodInfo] = &[
    MethodInfo { name: "isHttpEnabled", direct: true, doc: "function():boolean -- Returns whether HTTP requests can be made (config setting)." },
    MethodInfo { name: "request", direct: false, doc: "function(url:string[, postData:string[, headers:table[, method:string]]]):userdata -- Starts an HTTP request." },
    MethodInfo { name: "isTcpEnabled", direct: true, doc: "function():boolean -- Returns whether TCP connections can be made (config setting)." },
    MethodInfo { name: "connect", direct: false, doc: "function(address:string[, port:number]):userdata -- Opens a new TCP connection. Returns the handle of the connection." },
];

// ---------------------------------------------------------------------------

fn err<'a>(lua: &'a Lua, reason: &str) -> mlua::Result<MultiValue> {
    let mut out = MultiValue::new();
    out.push_back(Value::Nil);
    out.push_back(Value::String(lua.create_string(reason)?));
    Ok(out)
}

/// Drop a leading `self` table so both `handle.read(n)` and `handle:read(n)`
/// work, as they do on the OpenComputers userdata handle.
fn skip_self(args: &[Value]) -> &[Value] {
    if matches!(args.first(), Some(Value::Table(_))) {
        &args[1..]
    } else {
        args
    }
}

const ADDRESS_PARSE_ERROR: &str = "address could not be parsed or no valid port given";

/// Parse the `connect` address forms accepted by OpenComputers:
/// `host` + explicit port, `host:port`, and bracketed IPv6 (`[::1]:port`).
/// A bare IPv6 literal is accepted only with an explicit port argument.
fn parse_endpoint(address: &str, explicit_port: Option<i64>) -> Result<(String, u16), String> {
    if address.is_empty() {
        return Err(ADDRESS_PARSE_ERROR.into());
    }
    let address = address.strip_prefix("oc://").unwrap_or(address);
    if address.contains("://") {
        return Err("unsupported protocol".into());
    }
    if address.is_empty() {
        return Err(ADDRESS_PARSE_ERROR.into());
    }

    if let Some(rest) = address.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "invalid address".to_string())?;
        validate_host(host)?;
        if after.is_empty() {
            let port = explicit_port
                .map(checked_port)
                .transpose()?
                .ok_or_else(|| ADDRESS_PARSE_ERROR.to_string())?;
            return Ok((host.to_string(), port));
        }
        let port_text = after
            .strip_prefix(':')
            .ok_or_else(|| "invalid address".to_string())?;
        return Ok((host.to_string(), parse_port(port_text)?));
    }

    let colons = address.matches(':').count();
    if colons >= 2 {
        // Bare IPv6 literal; an embedded port requires brackets.
        validate_host(address)?;
        let port = explicit_port
            .map(checked_port)
            .transpose()?
            .ok_or_else(|| ADDRESS_PARSE_ERROR.to_string())?;
        return Ok((address.to_string(), port));
    }
    if colons == 1 {
        let (host, port_text) = address.split_once(':').unwrap();
        validate_host(host)?;
        return Ok((host.to_string(), parse_port(port_text)?));
    }

    validate_host(address)?;
    let port = explicit_port
        .map(checked_port)
        .transpose()?
        .ok_or_else(|| ADDRESS_PARSE_ERROR.to_string())?;
    Ok((address.to_string(), port))
}

fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.contains('/')
        || host.contains('\\')
    {
        return Err("invalid address".into());
    }
    Ok(())
}

fn parse_port(text: &str) -> Result<u16, String> {
    let value: i64 = text.parse().map_err(|_| "invalid port".to_string())?;
    checked_port(value)
}

fn checked_port(value: i64) -> Result<u16, String> {
    match value {
        1..=65535 => Ok(value as u16),
        _ => Err("invalid port".into()),
    }
}

/// Resolve and connect on the worker thread. `connect_timeout` bounds the
/// handshake (and is applied to each candidate address until the deadline).
fn connect_socket(host: &str, port: u16) -> Result<TcpStream, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve {}: {}", host, error))?;
    let deadline = Instant::now() + TCP_CONNECT_TIMEOUT;
    let mut saw_address = false;
    let mut last_error = None;
    for address in addresses {
        saw_address = true;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last_error = Some("connection timed out".to_string());
            break;
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    if !saw_address {
        return Err("could not resolve address".into());
    }
    Err(last_error.unwrap_or_else(|| "connection failed".into()))
}

fn validate_url(url: &str) -> Result<(), String> {
    match url.find("://") {
        Some(index) => match url[..index].to_ascii_lowercase().as_str() {
            "http" | "https" => Ok(()),
            _ => Err("unsupported protocol".into()),
        },
        None => Err("invalid address".into()),
    }
}

fn parse_headers(value: Option<&Value>) -> mlua::Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    if let Some(Value::Table(table)) = value {
        for pair in table.pairs::<Value, Value>() {
            let (key, value) = pair?;
            let key = match key {
                Value::String(s) => s.to_string_lossy().to_string(),
                _ => continue,
            };
            let value = match value {
                Value::String(s) => s.to_string_lossy().to_string(),
                Value::Integer(i) => i.to_string(),
                Value::Number(n) => n.to_string(),
                Value::Boolean(b) => b.to_string(),
                _ => continue,
            };
            headers.push((key, value));
        }
    }
    Ok(headers)
}

fn perform_request(
    url: &str,
    method: Option<String>,
    post: Option<Vec<u8>>,
    headers: Vec<(String, String)>,
    timeout: f64,
    user_agent: &str,
) -> Result<(ResponseInfo, Vec<u8>), String> {
    let mut config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .user_agent(user_agent);
    if timeout > 0.0 {
        config = config.timeout_global(Some(Duration::from_secs_f64(timeout)));
    }
    let agent = ureq::Agent::new_with_config(config.build());

    let method = method.unwrap_or_else(|| {
        if post.is_some() {
            "POST".to_string()
        } else {
            "GET".to_string()
        }
    });
    let body = post.unwrap_or_default();

    let method =
        ureq::http::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    let mut builder = ureq::http::Request::builder().method(method).uri(url);
    for (name, value) in &headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder.body(body).map_err(|e| e.to_string())?;
    let response = agent.run(request).map_err(|e| e.to_string())?;

    let status = response.status();
    let code = status.as_u16() as i32;
    let message = status.canonical_reason().unwrap_or("").to_string();

    let mut collected: Vec<(String, Vec<String>)> = Vec::new();
    for (name, value) in response.headers().iter() {
        let name = name.as_str().to_string();
        let value = String::from_utf8_lossy(value.as_bytes()).to_string();
        match collected.iter_mut().find(|(existing, _)| *existing == name) {
            Some((_, values)) => values.push(value),
            None => collected.push((name, vec![value])),
        }
    }

    let mut body = response.into_body();
    let bytes = body.read_to_vec().map_err(|e| e.to_string())?;

    Ok((
        ResponseInfo {
            code,
            message,
            headers: collected,
        },
        bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_http_and_https() {
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("https://example.com/path?q=1").is_ok());
        assert!(validate_url("HTTP://example.com").is_ok());
    }

    #[test]
    fn rejects_other_schemes_and_garbage() {
        assert_eq!(
            validate_url("ftp://example.com").unwrap_err(),
            "unsupported protocol"
        );
        assert_eq!(
            validate_url("example.com/no/scheme").unwrap_err(),
            "invalid address"
        );
    }

    #[test]
    fn parses_hostname_and_ipv4_endpoints() {
        assert_eq!(
            parse_endpoint("example.com", Some(80)).unwrap(),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            parse_endpoint("example.com:8080", None).unwrap(),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            parse_endpoint("127.0.0.1", Some(25565)).unwrap(),
            ("127.0.0.1".to_string(), 25565)
        );
        // An embedded port wins over the explicit argument, matching OC's URI
        // handling in checkUri.
        assert_eq!(
            parse_endpoint("127.0.0.1:9000", Some(25565)).unwrap(),
            ("127.0.0.1".to_string(), 9000)
        );
        assert_eq!(
            parse_endpoint("oc://example.com:25", None).unwrap(),
            ("example.com".to_string(), 25)
        );
    }

    #[test]
    fn parses_ipv6_endpoints() {
        assert_eq!(
            parse_endpoint("::1", Some(80)).unwrap(),
            ("::1".to_string(), 80)
        );
        assert_eq!(
            parse_endpoint("[::1]:8080", None).unwrap(),
            ("::1".to_string(), 8080)
        );
        assert_eq!(
            parse_endpoint("[::1]", Some(80)).unwrap(),
            ("::1".to_string(), 80)
        );
        assert_eq!(
            parse_endpoint("[2001:db8::5]:443", None).unwrap(),
            ("2001:db8::5".to_string(), 443)
        );
        assert!(parse_endpoint("::1", None).is_err());
    }

    #[test]
    fn rejects_invalid_endpoints() {
        assert_eq!(
            parse_endpoint("example.com", None).unwrap_err(),
            "address could not be parsed or no valid port given"
        );
        assert_eq!(
            parse_endpoint("", Some(80)).unwrap_err(),
            "address could not be parsed or no valid port given"
        );
        assert_eq!(
            parse_endpoint("example.com:0", None).unwrap_err(),
            "invalid port"
        );
        assert_eq!(
            parse_endpoint("example.com:65536", None).unwrap_err(),
            "invalid port"
        );
        assert_eq!(
            parse_endpoint("example.com:http", None).unwrap_err(),
            "invalid port"
        );
        assert_eq!(parse_endpoint("[::1]:", None).unwrap_err(), "invalid port");
        assert_eq!(
            parse_endpoint("http://example.com:80", None).unwrap_err(),
            "unsupported protocol"
        );
        assert_eq!(
            parse_endpoint("bad host", Some(80)).unwrap_err(),
            "invalid address"
        );
    }
}
