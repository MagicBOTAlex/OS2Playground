//! The `internet` component: HTTP(S) requests and raw TCP sockets performed on
//! background threads, mirroring the OpenComputers internet card.

use super::{arg_bytes, arg_string, multi1, Component, MethodInfo};
use crate::components::{Signal, SignalArg, SignalQueue};
use mlua::{Lua, MultiValue, Value, Variadic};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// OpenComputers clamps every `read` call to this many bytes by default.
pub const DEFAULT_MAX_READ_BUFFER: usize = 2048;

/// OpenComputers' default for `internet.maxTcpConnections`.
pub const DEFAULT_MAX_CONNECTIONS: usize = 4;

/// OpenComputers' default filtering rules.
pub const DEFAULT_FILTERING_RULES: &[&str] =
    &["removeme", "deny private", "deny bogon", "allow default"];

/// Upper bound for a TCP connect attempt.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CONNECTION_LOST: &str = "connection lost";

const ADDRESS_PARSE_ERROR: &str = "address could not be parsed or no valid port given";

// ---------------------------------------------------------------------------
// Address filtering

const BOGON_RANGES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "::/96",
    "64:ff9b::/96",
    "100::/64",
    "2001:10::/28",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
];

#[derive(Clone, Debug)]
struct IpRange {
    base: IpAddr,
    prefix: u8,
}

impl IpRange {
    fn parse(text: &str) -> Option<IpRange> {
        let (address_text, prefix_text) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let base: IpAddr = address_text.parse().ok()?;
        let max = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix_text {
            Some(prefix) => prefix.parse::<u8>().ok()?,
            None => max,
        };
        (prefix <= max).then_some(IpRange { base, prefix })
    }

    fn matches(&self, address: IpAddr) -> bool {
        match (self.base, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                matches_bytes(&base.octets(), &address.octets(), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                matches_bytes(&base.octets(), &address.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn matches_bytes(base: &[u8], address: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    let remainder = prefix % 8;
    if base[..full] != address[..full] {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remainder);
    (base[full] & mask) == (address[full] & mask)
}

#[derive(Clone, Debug)]
enum FilterPredicate {
    All,
    Never,
    Default,
    Private,
    Bogon,
    Ipv4,
    Ipv6,
    Ipv4EmbeddedIpv6,
    Ip(IpRange),
    Domain {
        name: String,
        addresses: Vec<IpAddr>,
    },
}

impl FilterPredicate {
    fn matches(&self, address: IpAddr, host: &str, bogon: &[IpRange]) -> bool {
        match self {
            FilterPredicate::All => true,
            FilterPredicate::Never => false,
            FilterPredicate::Default => !is_private(address) && !is_bogon(address, bogon),
            FilterPredicate::Private => is_private(address),
            FilterPredicate::Bogon => is_bogon(address, bogon),
            FilterPredicate::Ipv4 => matches!(address, IpAddr::V4(_)),
            FilterPredicate::Ipv6 => matches!(address, IpAddr::V6(_)),
            FilterPredicate::Ipv4EmbeddedIpv6 => embedded_ipv4(address).is_some(),
            FilterPredicate::Ip(range) => range.matches(address),
            FilterPredicate::Domain { name, addresses } => {
                host.eq_ignore_ascii_case(name) || addresses.contains(&address)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct FilterRule {
    allow: bool,
    predicates: Vec<FilterPredicate>,
}

impl FilterRule {
    fn matches(&self, address: IpAddr, host: &str, bogon: &[IpRange]) -> bool {
        self.predicates
            .iter()
            .all(|predicate| predicate.matches(address, host, bogon))
    }
}

/// Compiled `internet.filteringRules`. Any invalid rule disables all access,
/// matching OpenComputers' `internetAccessAllowed`.
#[derive(Clone, Debug)]
pub struct FilterSet {
    rules: Vec<FilterRule>,
    invalid: bool,
    bogon: Vec<IpRange>,
}

impl FilterSet {
    pub fn compile(rules: &[String]) -> FilterSet {
        let bogon: Vec<IpRange> = BOGON_RANGES
            .iter()
            .filter_map(|rule| IpRange::parse(rule))
            .collect();
        let mut set = FilterSet {
            rules: Vec::new(),
            invalid: false,
            bogon,
        };
        for rule in rules {
            let text = rule.trim();
            if text.is_empty() || text == "removeme" {
                continue;
            }
            let mut parts = text.split_whitespace();
            let allow = match parts.next() {
                Some("allow") => true,
                Some("deny") => false,
                _ => {
                    set.invalid = true;
                    continue;
                }
            };
            let mut predicates = Vec::new();
            let mut valid = true;
            for token in parts {
                match parse_predicate(token, allow) {
                    Some(predicate) => predicates.push(predicate),
                    None => {
                        valid = false;
                        break;
                    }
                }
            }
            if valid {
                set.rules.push(FilterRule { allow, predicates });
            } else {
                set.invalid = true;
            }
        }
        set
    }

    pub fn invalid(&self) -> bool {
        self.invalid
    }

    /// First matching rule wins. No match denies.
    pub fn is_allowed(&self, address: IpAddr, host: &str) -> bool {
        if self.invalid {
            return false;
        }
        if let IpAddr::V6(address6) = address {
            if let Some(embedded) = embedded_ipv4(address) {
                if self.decide(IpAddr::V4(embedded), host) == Some(false) {
                    return false;
                }
            }
            if let Some(embedded) = nat64_ipv4(address6) {
                if self.decide(IpAddr::V4(embedded), host) == Some(false) {
                    return false;
                }
            }
        }
        self.decide(address, host).unwrap_or(false)
    }

    fn decide(&self, address: IpAddr, host: &str) -> Option<bool> {
        self.rules
            .iter()
            .find(|rule| rule.matches(address, host, &self.bogon))
            .map(|rule| rule.allow)
    }
}

fn parse_predicate(token: &str, allow: bool) -> Option<FilterPredicate> {
    let (kind, value) = match token.split_once(':') {
        Some((kind, value)) => (kind, Some(value)),
        None => (token, None),
    };
    match kind {
        "all" => Some(FilterPredicate::All),
        "default" => Some(if allow {
            FilterPredicate::Default
        } else {
            FilterPredicate::Never
        }),
        "private" => Some(FilterPredicate::Private),
        "bogon" => Some(FilterPredicate::Bogon),
        "ipv4" => Some(FilterPredicate::Ipv4),
        "ipv6" => Some(FilterPredicate::Ipv6),
        "ipv4-embedded-ipv6" => Some(FilterPredicate::Ipv4EmbeddedIpv6),
        "ip" => Some(FilterPredicate::Ip(IpRange::parse(value?)?)),
        "domain" => {
            let name = value?;
            let addresses = resolve_domain(name)?;
            Some(FilterPredicate::Domain {
                name: name.to_ascii_lowercase(),
                addresses,
            })
        }
        _ => None,
    }
}

fn resolve_domain(domain: &str) -> Option<Vec<IpAddr>> {
    let addresses: Vec<IpAddr> = (domain, 0)
        .to_socket_addrs()
        .ok()?
        .map(|address| address.ip())
        .collect();
    if addresses.is_empty() {
        None
    } else {
        Some(addresses)
    }
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_private()
        }
        IpAddr::V6(address) => {
            let segment = address.segments()[0];
            address.is_unspecified()
                || address.is_loopback()
                || (segment & 0xffc0) == 0xfe80
                || (segment & 0xffc0) == 0xfec0
        }
    }
}

fn is_bogon(address: IpAddr, bogon: &[IpRange]) -> bool {
    bogon.iter().any(|range| range.matches(address))
}

fn embedded_ipv4(address: IpAddr) -> Option<Ipv4Addr> {
    match address {
        IpAddr::V4(_) => None,
        IpAddr::V6(address) => address.to_ipv4(),
    }
}

fn nat64_ipv4(address: std::net::Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = address.segments();
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0)
    {
        let octets = address.octets();
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Connection accounting

#[derive(Default)]
struct HttpState {
    done: bool,
    error: Option<String>,
    response: Option<ResponseInfo>,
    body: Vec<u8>,
    pos: usize,
    closed: bool,
    conn_id: u64,
}

struct ResponseInfo {
    code: i32,
    message: String,
    headers: Vec<(String, Vec<String>)>,
}

enum TcpStatus {
    Connecting,
    Connected,
    Failed,
    Closed,
}

struct TcpState {
    status: TcpStatus,
    stream: Option<TcpStream>,
    eof: bool,
    failure_reported: bool,
    notified: bool,
    id: u64,
}

enum ConnectionEntry {
    Http(Weak<Mutex<HttpState>>),
    Tcp(Weak<Mutex<TcpState>>),
}

impl ConnectionEntry {
    fn alive(&self) -> bool {
        match self {
            ConnectionEntry::Http(state) => state.strong_count() > 0,
            ConnectionEntry::Tcp(state) => state.strong_count() > 0,
        }
    }
}

struct ConnectionRegistry {
    max: usize,
    next: u64,
    entries: HashMap<u64, ConnectionEntry>,
}

impl ConnectionRegistry {
    fn new(max: usize) -> ConnectionRegistry {
        ConnectionRegistry {
            max,
            next: 1,
            entries: HashMap::new(),
        }
    }

    fn reserve(&mut self) -> Option<u64> {
        self.entries.retain(|_, entry| entry.alive());
        if self.entries.len() >= self.max {
            return None;
        }
        let id = self.next;
        self.next += 1;
        Some(id)
    }

    fn insert_http(&mut self, id: u64, state: Weak<Mutex<HttpState>>) {
        self.entries.insert(id, ConnectionEntry::Http(state));
    }

    fn insert_tcp(&mut self, id: u64, state: Weak<Mutex<TcpState>>) {
        self.entries.insert(id, ConnectionEntry::Tcp(state));
    }

    fn release(&mut self, id: u64) {
        self.entries.remove(&id);
    }

    fn tcp_states(&mut self) -> Vec<Arc<Mutex<TcpState>>> {
        self.entries.retain(|_, entry| entry.alive());
        self.entries
            .values()
            .filter_map(|entry| match entry {
                ConnectionEntry::Tcp(state) => state.upgrade(),
                ConnectionEntry::Http(_) => None,
            })
            .collect()
    }

    fn close_all(&mut self) {
        let entries: Vec<ConnectionEntry> = self.entries.drain().map(|(_, entry)| entry).collect();
        for entry in entries {
            match entry {
                ConnectionEntry::Http(state) => {
                    if let Some(state) = state.upgrade() {
                        let mut state = state.lock().unwrap();
                        state.closed = true;
                        state.body.clear();
                    }
                }
                ConnectionEntry::Tcp(state) => {
                    if let Some(state) = state.upgrade() {
                        let mut state = state.lock().unwrap();
                        if let Some(stream) = state.stream.take() {
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        state.status = TcpStatus::Closed;
                        state.eof = false;
                    }
                }
            }
        }
    }
}

fn socket_id(id: u64) -> String {
    format!("ocplay-tcp-{:016x}", id)
}

// ---------------------------------------------------------------------------
// Component

/// The internet card. Network work runs on background threads so the machine
/// keeps rendering while requests and connections are in flight.
pub struct Internet {
    pub http_enabled: bool,
    pub tcp_enabled: bool,
    pub timeout: f64,
    pub user_agent: String,
    pub max_read_buffer: usize,
    filters: Arc<FilterSet>,
    connections: Arc<Mutex<ConnectionRegistry>>,
}

impl Internet {
    pub fn new(
        http_enabled: bool,
        tcp_enabled: bool,
        timeout: f64,
        user_agent: String,
        max_connections: usize,
        max_read_buffer: usize,
        filtering_rules: Vec<String>,
    ) -> Internet {
        Internet {
            http_enabled,
            tcp_enabled,
            timeout,
            user_agent,
            max_read_buffer,
            filters: Arc::new(FilterSet::compile(&filtering_rules)),
            connections: Arc::new(Mutex::new(ConnectionRegistry::new(max_connections))),
        }
    }

    fn access_allowed(&self) -> bool {
        (self.http_enabled || self.tcp_enabled) && !self.filters.invalid()
    }

    fn reserve(&self) -> Option<u64> {
        self.connections.lock().unwrap().reserve()
    }

    fn register_http(&self, id: u64, state: Weak<Mutex<HttpState>>) {
        self.connections.lock().unwrap().insert_http(id, state);
    }

    fn register_tcp(&self, id: u64, state: Weak<Mutex<TcpState>>) {
        self.connections.lock().unwrap().insert_tcp(id, state);
    }

    fn release(&self, id: u64) {
        self.connections.lock().unwrap().release(id);
    }

    /// Close every HTTP/TCP handle. Called when the machine stops or reboots.
    pub fn close_all(&self) {
        self.connections.lock().unwrap().close_all();
    }

    /// Emit `internet_ready` once per readability event for connected sockets.
    pub fn poll_signals(&self, signals: &SignalQueue) {
        let states = self.connections.lock().unwrap().tcp_states();
        for state in states {
            let mut state = state.lock().unwrap();
            if !matches!(state.status, TcpStatus::Connected) || state.notified {
                continue;
            }
            let ready = match state.stream.as_ref() {
                Some(stream) => {
                    let mut byte = [0u8; 1];
                    match stream.peek(&mut byte) {
                        Ok(_) => true,
                        Err(error) => error.kind() != ErrorKind::WouldBlock,
                    }
                }
                None => false,
            };
            if ready {
                state.notified = true;
                let signal =
                    Signal::new("internet_ready").with(SignalArg::Str(socket_id(state.id)));
                signals.borrow_mut().push_back(signal);
            }
        }
    }

    fn connect(&self, lua: &Lua, args: &[Value]) -> mlua::Result<MultiValue> {
        let address = arg_string(args, 0)?;
        if !self.access_allowed() {
            return err(lua, "internet access is unavailable");
        }
        if !self.tcp_enabled {
            return err(lua, "tcp connections are unavailable");
        }

        let explicit_port = match args.get(1) {
            None | Some(Value::Nil) => None,
            Some(_) => Some(super::arg_int(args, 1)?),
        };
        let (host, port) = match parse_endpoint(&address, explicit_port) {
            Ok(endpoint) => endpoint,
            Err(reason) => return err(lua, &reason),
        };

        let conn_id = match self.reserve() {
            Some(id) => id,
            None => return err(lua, "too many open connections"),
        };
        let state = Arc::new(Mutex::new(TcpState {
            status: TcpStatus::Connecting,
            stream: None,
            eof: false,
            failure_reported: false,
            notified: false,
            id: conn_id,
        }));
        self.register_tcp(conn_id, Arc::downgrade(&state));

        let worker = state.clone();
        let filters = self.filters.clone();
        let registry = self.connections.clone();
        std::thread::spawn(move || {
            let outcome = connect_filtered(&host, port, &filters);
            let mut state = worker.lock().unwrap();
            match outcome {
                Ok(stream) if !matches!(state.status, TcpStatus::Closed) => {
                    match stream.set_nonblocking(true) {
                        Ok(()) => {
                            state.stream = Some(stream);
                            state.status = TcpStatus::Connected;
                        }
                        Err(_) => {
                            state.status = TcpStatus::Failed;
                            registry.lock().unwrap().release(conn_id);
                        }
                    }
                }
                Ok(stream) => drop(stream),
                Err(()) => {
                    if !matches!(state.status, TcpStatus::Closed) {
                        state.status = TcpStatus::Failed;
                    }
                    registry.lock().unwrap().release(conn_id);
                }
            }
        });

        let handle = lua.create_table()?;

        let finish_state = state.clone();
        handle.set(
            "finishConnect",
            lua.create_function(move |lua, _: Variadic<Value>| {
                let mut state = finish_state.lock().unwrap();
                if matches!(state.status, TcpStatus::Connecting) {
                    return Ok(multi1(Value::Boolean(false)));
                }
                if matches!(state.status, TcpStatus::Connected) {
                    return Ok(multi1(Value::Boolean(true)));
                }
                if matches!(state.status, TcpStatus::Failed) {
                    if !state.failure_reported {
                        state.failure_reported = true;
                        return Ok(multi1(Value::Boolean(false)));
                    }
                    state.status = TcpStatus::Closed;
                }
                err(lua, CONNECTION_LOST)
            })?,
        )?;

        let read_state = state.clone();
        let read_filters = self.max_read_buffer;
        let read_registry = self.connections.clone();
        handle.set(
            "read",
            lua.create_function(move |lua, args: Variadic<Value>| {
                let args = skip_self(args.as_ref());
                let limit = match args.first() {
                    None | Some(Value::Nil) => read_filters,
                    Some(_) => super::arg_int(args, 0)?.max(0) as usize,
                }
                .min(read_filters);

                let mut state = read_state.lock().unwrap();
                if matches!(state.status, TcpStatus::Failed) {
                    state.status = TcpStatus::Closed;
                    read_registry.lock().unwrap().release(state.id);
                    return err(lua, CONNECTION_LOST);
                }
                if matches!(state.status, TcpStatus::Closed) {
                    if state.eof {
                        return Ok(multi1(Value::Nil));
                    }
                    return err(lua, CONNECTION_LOST);
                }
                if matches!(state.status, TcpStatus::Connecting) {
                    return Ok(multi1(Value::String(lua.create_string("")?)));
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
                        if let Some(stream) = state.stream.take() {
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        state.status = TcpStatus::Closed;
                        state.eof = true;
                        read_registry.lock().unwrap().release(state.id);
                        Ok(multi1(Value::Nil))
                    }
                    Ok(read) => {
                        state.notified = false;
                        buffer.truncate(read);
                        Ok(multi1(Value::String(lua.create_string(&buffer)?)))
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        state.notified = false;
                        Ok(multi1(Value::String(lua.create_string("")?)))
                    }
                    Err(_) => {
                        if let Some(stream) = state.stream.take() {
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        state.status = TcpStatus::Closed;
                        read_registry.lock().unwrap().release(state.id);
                        err(lua, CONNECTION_LOST)
                    }
                }
            })?,
        )?;

        let write_state = state.clone();
        let write_registry = self.connections.clone();
        handle.set(
            "write",
            lua.create_function(move |lua, args: Variadic<Value>| {
                let args = skip_self(args.as_ref());
                let data = arg_bytes(args, 0)?;
                let mut state = write_state.lock().unwrap();
                if matches!(state.status, TcpStatus::Connecting) {
                    return Ok(multi1(Value::Integer(0)));
                }
                if !matches!(state.status, TcpStatus::Connected) {
                    if matches!(state.status, TcpStatus::Failed) {
                        state.status = TcpStatus::Closed;
                    }
                    write_registry.lock().unwrap().release(state.id);
                    return err(lua, CONNECTION_LOST);
                }
                let outcome = {
                    let stream = state.stream.as_mut().unwrap();
                    stream.write(&data)
                };
                match outcome {
                    Ok(written) => Ok(multi1(Value::Integer(written as i64))),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        Ok(multi1(Value::Integer(0)))
                    }
                    Err(_) => {
                        if let Some(stream) = state.stream.take() {
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        state.status = TcpStatus::Closed;
                        write_registry.lock().unwrap().release(state.id);
                        err(lua, CONNECTION_LOST)
                    }
                }
            })?,
        )?;

        let close_state = state.clone();
        let close_registry = self.connections.clone();
        handle.set(
            "close",
            lua.create_function(move |_, _: Variadic<Value>| {
                let mut state = close_state.lock().unwrap();
                if let Some(stream) = state.stream.take() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                state.status = TcpStatus::Closed;
                state.eof = false;
                close_registry.lock().unwrap().release(state.id);
                Ok(())
            })?,
        )?;

        let id_state = state.clone();
        handle.set(
            "id",
            lua.create_function(move |lua, _: Variadic<Value>| {
                let state = id_state.lock().unwrap();
                Ok(multi1(Value::String(
                    lua.create_string(socket_id(state.id))?,
                )))
            })?,
        )?;

        Ok(multi1(Value::Table(handle)))
    }

    fn request(&self, lua: &Lua, args: &[Value]) -> mlua::Result<MultiValue> {
        let url = arg_string(args, 0)?;
        if !self.access_allowed() {
            return err(lua, "internet access is unavailable");
        }
        if !self.http_enabled {
            return err(lua, "http requests are unavailable");
        }
        let target = match parse_http_url(&url) {
            Ok(target) => target,
            Err(reason) => return err(lua, &reason),
        };

        let post = match args.get(1) {
            Some(Value::String(s)) => Some(s.as_bytes().to_vec()),
            _ => None,
        };
        let headers = parse_headers(args.get(2))?;
        let method = match args.get(3) {
            Some(Value::String(s)) => Some(s.to_string_lossy().to_string()),
            _ => None,
        };

        let conn_id = match self.reserve() {
            Some(id) => id,
            None => return err(lua, "too many open connections"),
        };
        let state = Arc::new(Mutex::new(HttpState {
            conn_id,
            ..HttpState::default()
        }));
        self.register_http(conn_id, Arc::downgrade(&state));

        let worker = state.clone();
        let timeout = self.timeout;
        let user_agent = self.user_agent.clone();
        let url_owned = url.clone();
        let filters = self.filters.clone();
        let registry = self.connections.clone();
        std::thread::spawn(move || {
            let outcome = match check_host_allowed(&target.host, target.port, &filters) {
                Ok(()) => perform_request(&url_owned, method, post, headers, timeout, &user_agent),
                Err(reason) => Err(reason),
            };
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
                Err(reason) => {
                    state.error = Some(reason);
                    registry.lock().unwrap().release(conn_id);
                }
            }
        });

        let handle = lua.create_table()?;

        let read_state = state.clone();
        let read_limit = self.max_read_buffer;
        handle.set(
            "read",
            lua.create_function(move |lua, n: Option<i64>| {
                let mut state = read_state.lock().unwrap();
                if state.closed {
                    return err(lua, CONNECTION_LOST);
                }
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
                let limit = limit.min(read_limit);
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
                if state.closed {
                    return err(lua, CONNECTION_LOST);
                }
                if let Some(reason) = &state.error {
                    return err(lua, reason);
                }
                Ok(multi1(Value::Boolean(state.done)))
            })?,
        )?;

        let close_registry = self.connections.clone();
        handle.set(
            "close",
            lua.create_function(move |_, ()| {
                let mut state = state.lock().unwrap();
                state.closed = true;
                state.body.clear();
                close_registry.lock().unwrap().release(state.conn_id);
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
            "isHttpEnabled" => Ok(multi1(Value::Boolean(self.http_enabled))),
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

fn err(lua: &Lua, reason: &str) -> mlua::Result<MultiValue> {
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

/// Mirror OC's `checkUri` where practical: accept URI schemes, `host:port`,
/// `host/path` plus an explicit port, and bracketed IPv6. An embedded port wins.
/// A bare IPv6 literal is rejected because Java's URI parser treats it as a
/// scheme/host ambiguity, so OC rejects it too.
fn parse_endpoint(address: &str, explicit_port: Option<i64>) -> Result<(String, u16), String> {
    if address.is_empty() {
        return Err(ADDRESS_PARSE_ERROR.into());
    }
    let address = match address.split_once("://") {
        Some((scheme, rest)) => {
            let valid = !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
            if !valid || rest.is_empty() {
                return Err("invalid address".into());
            }
            rest
        }
        None => address,
    };

    let authority_end = address.find(['/', '?', '#']).unwrap_or(address.len());
    let authority = &address[..authority_end];
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return Err(ADDRESS_PARSE_ERROR.into());
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "invalid address".to_string())?;
        if host.parse::<Ipv6Addr>().is_err() {
            return Err("invalid address".into());
        }
        validate_host(host)?;
        let port = if let Some(port_text) = after.strip_prefix(':') {
            parse_port(port_text)?
        } else if after.is_empty() {
            explicit_port
                .map(checked_port)
                .transpose()?
                .ok_or_else(|| ADDRESS_PARSE_ERROR.to_string())?
        } else {
            return Err("invalid address".into());
        };
        return Ok((host.to_string(), port));
    }

    let colons = authority.matches(':').count();
    if colons > 1 {
        // Bare IPv6 literal; OC's URI parser does not accept it.
        return Err(ADDRESS_PARSE_ERROR.into());
    }
    let (host, embedded_port) = if colons == 1 {
        let (host, port_text) = authority.split_once(':').unwrap();
        (host, Some(parse_port(port_text)?))
    } else {
        (authority, None)
    };
    validate_host(host)?;
    let port = match embedded_port {
        Some(port) => port,
        None => explicit_port
            .map(checked_port)
            .transpose()?
            .ok_or_else(|| ADDRESS_PARSE_ERROR.to_string())?,
    };
    Ok((host.to_string(), port))
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

/// Resolve and connect on the worker thread, skipping addresses that the
/// filtering rules deny. The 10 second deadline covers all candidates.
fn connect_filtered(host: &str, port: u16, filters: &FilterSet) -> Result<TcpStream, ()> {
    let addresses: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(|_| ())?.collect();
    if addresses.is_empty() {
        return Err(());
    }
    let deadline = Instant::now() + TCP_CONNECT_TIMEOUT;
    for address in addresses {
        if !filters.is_allowed(address.ip(), host) {
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Ok(stream) = TcpStream::connect_timeout(&address, remaining) {
            return Ok(stream);
        }
    }
    Err(())
}

#[derive(Debug)]
struct HttpTarget {
    host: String,
    port: u16,
}

fn parse_http_url(url: &str) -> Result<HttpTarget, String> {
    let uri: ureq::http::Uri = url.parse().map_err(|_| "invalid address".to_string())?;
    let scheme = uri.scheme_str().unwrap_or("");
    if scheme.is_empty() {
        return Err("invalid address".into());
    }
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err("unsupported protocol".into());
    }
    let host = uri.host().ok_or_else(|| "invalid address".to_string())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("invalid address".into());
    }
    let port = uri
        .port_u16()
        .unwrap_or(if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        });
    Ok(HttpTarget {
        host: host.to_string(),
        port,
    })
}

fn check_host_allowed(host: &str, port: u16, filters: &FilterSet) -> Result<(), String> {
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| "could not resolve host".to_string())?
        .collect();
    if addresses.is_empty() {
        return Err("could not resolve host".into());
    }
    // HTTP is resolved again by the HTTP client, so require every candidate to
    // be allowed to avoid falling back to a denied address.
    if addresses
        .iter()
        .all(|address| filters.is_allowed(address.ip(), host))
    {
        Ok(())
    } else {
        Err("address is not allowed".into())
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

    let method = ureq::http::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
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

    fn rules(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn default_rules() -> Vec<String> {
        DEFAULT_FILTERING_RULES
            .iter()
            .map(|value| value.to_string())
            .collect()
    }

    #[test]
    fn default_rules_deny_loopback_and_allow_public() {
        let filters = FilterSet::compile(&default_rules());
        assert!(!filters.invalid());
        assert_eq!(filters.bogon.len(), BOGON_RANGES.len());
        assert!(!filters.is_allowed("127.0.0.1".parse().unwrap(), "127.0.0.1"));
        assert!(!filters.is_allowed("::1".parse().unwrap(), "::1"));
        assert!(!filters.is_allowed("::ffff:127.0.0.1".parse().unwrap(), "::ffff:127.0.0.1"));
        assert!(filters.is_allowed("1.1.1.1".parse().unwrap(), "1.1.1.1"));
    }

    #[test]
    fn allow_rule_permits_loopback_and_first_match_wins() {
        let filters = FilterSet::compile(&rules(&["allow ip:127.0.0.1/8", "deny all"]));
        assert!(filters.is_allowed("127.0.0.1".parse().unwrap(), "127.0.0.1"));

        let allow_first = FilterSet::compile(&rules(&["allow all", "deny all"]));
        assert!(allow_first.is_allowed("127.0.0.1".parse().unwrap(), "127.0.0.1"));

        let deny_first = FilterSet::compile(&rules(&["deny all", "allow all"]));
        assert!(!deny_first.is_allowed("127.0.0.1".parse().unwrap(), "127.0.0.1"));
    }

    #[test]
    fn no_match_denies_and_invalid_rules_disable_access() {
        let no_match = FilterSet::compile(&rules(&["allow ip:10.0.0.0/8"]));
        assert!(!no_match.is_allowed("1.1.1.1".parse().unwrap(), "1.1.1.1"));

        let invalid = FilterSet::compile(&rules(&["allow ip:not-an-ip"]));
        assert!(invalid.invalid());
        assert!(!invalid.is_allowed("1.1.1.1".parse().unwrap(), "1.1.1.1"));

        let disabled = Internet::new(
            true,
            true,
            0.0,
            "test".into(),
            4,
            2048,
            rules(&["allow ip:not-an-ip"]),
        );
        assert!(!disabled.access_allowed());

        let tcp_only = Internet::new(
            false,
            true,
            0.0,
            "test".into(),
            4,
            2048,
            rules(&["allow all"]),
        );
        assert!(tcp_only.access_allowed());
        assert!(!tcp_only.http_enabled);
        assert!(tcp_only.tcp_enabled);
    }

    #[test]
    fn http_filtering_uses_the_same_rules() {
        let denied = FilterSet::compile(&default_rules());
        assert_eq!(
            check_host_allowed("127.0.0.1", 80, &denied).unwrap_err(),
            "address is not allowed"
        );

        let allowed = FilterSet::compile(&rules(&["allow ip:127.0.0.1/8"]));
        assert!(check_host_allowed("127.0.0.1", 80, &allowed).is_ok());
    }

    #[test]
    fn predicate_families_match() {
        let filters = FilterSet::compile(&rules(&[
            "allow ip:127.0.0.1/8",
            "allow ipv4",
            "allow bogon",
            "allow private",
            "allow domain:localhost",
            "allow default",
        ]));
        assert!(!filters.invalid());
        let ipv6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(filters.is_allowed(ipv6, "dns.google"));
    }

    #[test]
    fn connection_registry_limit_releases_slots() {
        let mut registry = ConnectionRegistry::new(2);
        let http_state = Arc::new(Mutex::new(HttpState::default()));
        let tcp_state = Arc::new(Mutex::new(TcpState {
            status: TcpStatus::Connecting,
            stream: None,
            eof: false,
            failure_reported: false,
            notified: false,
            id: 0,
        }));
        let first = registry.reserve().unwrap();
        registry.insert_http(first, Arc::downgrade(&http_state));
        let second = registry.reserve().unwrap();
        registry.insert_tcp(second, Arc::downgrade(&tcp_state));
        assert!(registry.reserve().is_none());
        registry.release(first);
        assert!(registry.reserve().is_some());
    }

    #[test]
    fn close_all_drops_socket_streams() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let state = Arc::new(Mutex::new(TcpState {
            status: TcpStatus::Connected,
            stream: Some(client),
            eof: false,
            failure_reported: false,
            notified: false,
            id: 1,
        }));
        let mut registry = ConnectionRegistry::new(4);
        let id = registry.reserve().unwrap();
        registry.insert_tcp(id, Arc::downgrade(&state));

        registry.close_all();

        {
            let state = state.lock().unwrap();
            assert!(matches!(&state.status, TcpStatus::Closed));
            assert!(state.stream.is_none());
        }
        let mut buffer = [0u8; 1];
        assert_eq!(server.read(&mut buffer).unwrap(), 0);
    }

    #[test]
    fn accepts_http_and_https() {
        assert!(parse_http_url("http://example.com").is_ok());
        assert!(parse_http_url("https://example.com/path?q=1").is_ok());
        assert!(parse_http_url("HTTP://example.com").is_ok());
    }

    #[test]
    fn rejects_other_schemes_and_garbage() {
        assert_eq!(
            parse_http_url("ftp://example.com").unwrap_err(),
            "unsupported protocol"
        );
        assert_eq!(
            parse_http_url("example.com/no/scheme").unwrap_err(),
            "invalid address"
        );
    }

    #[test]
    fn parses_address_matrix() {
        assert_eq!(
            parse_endpoint("example.com", Some(80)).unwrap(),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            parse_endpoint("example.com:8080", None).unwrap(),
            ("example.com".to_string(), 8080)
        );
        // Embedded ports win over the explicit argument.
        assert_eq!(
            parse_endpoint("127.0.0.1:9000", Some(25565)).unwrap(),
            ("127.0.0.1".to_string(), 9000)
        );
        assert_eq!(
            parse_endpoint("http://example.com", Some(80)).unwrap(),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            parse_endpoint("https://example.com:443", None).unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_endpoint("http://example.com:8080/path?q=1", None).unwrap(),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            parse_endpoint("example.com/path", Some(80)).unwrap(),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            parse_endpoint("oc://example.com:25", None).unwrap(),
            ("example.com".to_string(), 25)
        );
        assert_eq!(
            parse_endpoint("[::1]:8080", None).unwrap(),
            ("::1".to_string(), 8080)
        );
        assert_eq!(
            parse_endpoint("[::1]", Some(80)).unwrap(),
            ("::1".to_string(), 80)
        );
    }

    #[test]
    fn rejects_invalid_addresses() {
        assert_eq!(
            parse_endpoint("example.com", None).unwrap_err(),
            ADDRESS_PARSE_ERROR
        );
        assert_eq!(
            parse_endpoint("::1", Some(80)).unwrap_err(),
            ADDRESS_PARSE_ERROR
        );
        assert_eq!(
            parse_endpoint("", Some(80)).unwrap_err(),
            ADDRESS_PARSE_ERROR
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
        assert_eq!(
            parse_endpoint("http://example.com:80", Some(80)).unwrap(),
            ("example.com".to_string(), 80)
        );
        assert_eq!(parse_endpoint("[::1]:", None).unwrap_err(), "invalid port");
        assert_eq!(
            parse_endpoint("[bad]:80", None).unwrap_err(),
            "invalid address"
        );
        assert_eq!(
            parse_endpoint("bad host", Some(80)).unwrap_err(),
            "invalid address"
        );
    }
}
