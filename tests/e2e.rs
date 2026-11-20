//! End-to-end tests: run the compiled `ocplay` binary against temporary
//! computers and assert on its output.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ocplay-test-{}-{}-{}-{}",
        tag,
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A minimal config that boots the built-in OpenOS and never waits on exit.
fn base_config(extra_mount: Option<&Path>) -> String {
    base_config_with(extra_mount, false, true)
}

fn base_config_with_tcp(extra_mount: Option<&Path>, tcp: bool) -> String {
    base_config_with(extra_mount, tcp, true)
}

fn base_config_with(extra_mount: Option<&Path>, tcp: bool, allow_loopback: bool) -> String {
    let mut config = String::from(
        "name: test\n\
         memory: 512\n\
         cpu:\n  tier: 2\n\
         gpu:\n  tier: 3\n  screen:\n    width: 80\n    height: 25\n    maxDepth: 8\n\
         filesystems:\n\
         \x20 - label: openos\n    path: builtin\n    mount: /\n    readonly: false\n",
    );
    if let Some(path) = extra_mount {
        config.push_str(&format!(
            "  - label: out\n    path: {}\n    mount: /out\n    readonly: false\n",
            path.display()
        ));
    }
    let filtering = if allow_loopback {
        "  filteringRules:\n    - allow ip:127.0.0.1/8\n"
    } else {
        ""
    };
    config.push_str(&format!(
        "components:\n  keyboard: true\n  mouse: false\n\
         internet:\n  enabled: true\n  timeout: 30\n  tcp: {}\n{}\
         run:\n  timeout: 0\n  interactive: false\n  terminateDelay: 0\n",
        tcp, filtering
    ));
    config
}

fn run_ocplay(config: &Path, script: Option<&Path>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ocplay"));
    command.arg(config);
    if let Some(script) = script {
        command.arg(script);
    }
    command.args(args);
    command.output().expect("failed to run ocplay")
}

#[test]
fn boots_openos_and_runs_a_script() {
    let dir = temp_dir("run");
    let config = dir.join("computer.yaml");
    fs::write(&config, base_config(None)).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        r#"require("term").clear()
print("OCPLAY_MARKER_OK")
require("computer").shutdown()"#,
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stdout.contains("OCPLAY_MARKER_OK"), "stdout: {stdout}");
}

#[test]
fn internet_get_returns_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = socket.read(&mut request);
        let body = "hello-from-test";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket.write_all(response.as_bytes()).unwrap();
    });

    let dir = temp_dir("internet");
    let config = dir.join("computer.yaml");
    fs::write(&config, base_config(None)).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        format!(
            r#"local internet = require("internet")
local chunks = {{}}
for chunk in internet.request("http://{addr}/") do
  chunks[#chunks + 1] = chunk
end
print("BODY:" .. table.concat(chunks))
require("computer").shutdown()"#
        ),
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &[]);
    server.join().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("BODY:hello-from-test"), "stdout: {stdout}");
}

#[test]
fn internet_tcp_echo_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut request = [0u8; 64];
        let read = socket.read(&mut request).unwrap_or(0);
        let mut response = b"ECHO:".to_vec();
        response.extend_from_slice(&request[..read]);
        socket.write_all(&response).unwrap();
        // Signal EOF so the guest's read loop terminates deterministically.
        let _ = socket.shutdown(Shutdown::Write);
    });

    let dir = temp_dir("tcp");
    let config = dir.join("computer.yaml");
    fs::write(&config, base_config_with_tcp(None, true)).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        format!(
            r#"local component = require("component")
local computer = require("computer")
local socket, reason = component.internet.connect("127.0.0.1", {port})
if not socket then error(reason) end
local deadline = computer.uptime() + 5
while not socket.finishConnect() do
  if computer.uptime() > deadline then error("connect timeout") end
  os.sleep(0.01)
end
print("TCP_ID:" .. socket.id())
local written = socket.write("ping")
print("TCP_WRITTEN:" .. tostring(written))
local received = ""
local eof_reason = "none"
deadline = computer.uptime() + 5
while true do
  local chunk, why = socket.read(64)
  if chunk == nil then
    eof_reason = tostring(why)
    break
  end
  received = received .. chunk
  if computer.uptime() > deadline then error("read timeout") end
  os.sleep(0.01)
end
print("TCP_RECEIVED:" .. received)
print("TCP_EOF_REASON:" .. eof_reason)
socket.close()
socket.close()
local after, after_reason = socket.read(1)
print("TCP_READ_AFTER_CLOSE:" .. tostring(after) .. ":" .. tostring(after_reason))
local wrote, wrote_reason = socket.write("x")
print("TCP_WRITE_AFTER_CLOSE:" .. tostring(wrote) .. ":" .. tostring(wrote_reason))
require("computer").shutdown()"#,
            port = addr.port()
        ),
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &[]);
    server.join().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(stdout.contains("TCP_ID:ocplay-tcp-"), "stdout: {stdout}");
    assert!(stdout.contains("TCP_WRITTEN:4"), "stdout: {stdout}");
    assert!(
        stdout.contains("TCP_RECEIVED:ECHO:ping"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("TCP_EOF_REASON:nil"), "stdout: {stdout}");
    assert!(
        stdout.contains("TCP_READ_AFTER_CLOSE:nil:connection lost"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("TCP_WRITE_AFTER_CLOSE:nil:connection lost"),
        "stdout: {stdout}"
    );
}

#[test]
fn internet_tcp_disabled_returns_error() {
    let dir = temp_dir("tcpoff");
    let config = dir.join("computer.yaml");
    fs::write(&config, base_config(None)).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        r#"local component = require("component")
local socket, reason = component.internet.connect("127.0.0.1", 1234)
print("TCP_DISABLED:" .. tostring(socket) .. ":" .. tostring(reason))
print("FLAGS:" .. tostring(component.internet.isHttpEnabled()) .. ":" .. tostring(component.internet.isTcpEnabled()))
require("computer").shutdown()"#,
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("TCP_DISABLED:nil:tcp connections are unavailable"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("FLAGS:true:false"), "stdout: {stdout}");
}

#[test]
fn internet_connection_limit_is_shared_and_releases() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let dir = temp_dir("tcplimit");
    let config = dir.join("computer.yaml");
    fs::write(&config, base_config_with_tcp(None, true)).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        format!(
            r#"local component = require("component")
local computer = require("computer")
local opened = {{}}
for i = 1, 4 do
  local socket, reason = component.internet.connect("127.0.0.1", {port})
  if not socket then error("open " .. i .. ": " .. tostring(reason)) end
  local deadline = computer.uptime() + 5
  while not socket.finishConnect() do
    if computer.uptime() > deadline then error("connect timeout " .. i) end
    os.sleep(0.01)
  end
  opened[i] = socket
end
local fifth, fifth_reason = component.internet.connect("127.0.0.1", {port})
print("LIMIT_TCP:" .. tostring(fifth) .. ":" .. tostring(fifth_reason))
local request, request_reason = component.internet.request("http://127.0.0.1:{port}/")
print("LIMIT_HTTP:" .. tostring(request) .. ":" .. tostring(request_reason))
opened[1].close()
local sixth, sixth_reason = component.internet.connect("127.0.0.1", {port})
print("LIMIT_REOPEN:" .. tostring(sixth ~= nil) .. ":" .. tostring(sixth_reason))
if sixth then
  local deadline = computer.uptime() + 5
  while not sixth.finishConnect() do
    if computer.uptime() > deadline then error("reopen timeout") end
    os.sleep(0.01)
  end
  sixth.close()
end
for i = 2, 4 do opened[i].close() end
require("computer").shutdown()"#,
            port = addr.port()
        ),
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("LIMIT_TCP:nil:too many open connections"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("LIMIT_HTTP:nil:too many open connections"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("LIMIT_REOPEN:true"), "stdout: {stdout}");
}

#[test]
fn internet_http_and_tcp_flags_are_independent() {
    let dir = temp_dir("tcpflags");
    let config = dir.join("computer.yaml");
    let config_text = base_config_with_tcp(None, true)
        .replace("internet:\n  enabled: true", "internet:\n  enabled: false");
    fs::write(&config, config_text).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        r#"local component = require("component")
print("FLAGS:" .. tostring(component.internet.isHttpEnabled()) .. ":" .. tostring(component.internet.isTcpEnabled()))
local request, reason = component.internet.request("http://127.0.0.1:1/")
print("HTTP_OFF:" .. tostring(request) .. ":" .. tostring(reason))
require("computer").shutdown()"#,
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("FLAGS:false:true"), "stdout: {stdout}");
    assert!(
        stdout.contains("HTTP_OFF:nil:http requests are unavailable"),
        "stdout: {stdout}"
    );
}

#[test]
fn internet_filtering_denies_loopback_by_default() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();

    let dir = temp_dir("tcpfilter");
    let config = dir.join("computer.yaml");
    fs::write(&config, base_config_with(None, true, false)).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        format!(
            r#"local component = require("component")
local computer = require("computer")
local socket = assert(component.internet.connect("127.0.0.1", {port}))
local saw_false = false
local connected = false
local final_reason = "none"
local deadline = computer.uptime() + 5
while computer.uptime() < deadline do
  local ok, value, reason = pcall(socket.finishConnect)
  if not ok then
    print("FILTER_HARD:" .. tostring(value))
    break
  end
  if value == true then
    connected = true
    break
  elseif value == false then
    saw_false = true
  elseif value == nil then
    final_reason = tostring(reason)
    break
  end
  os.sleep(0.02)
end
print("FILTER_RESULT:" .. tostring(connected) .. ":" .. tostring(saw_false) .. ":" .. final_reason)
socket.close()
require("computer").shutdown()"#,
            port = addr.port()
        ),
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("FILTER_RESULT:false:true:connection lost"),
        "stdout: {stdout}"
    );
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "filtered client must not reach the listener"
    );
}

#[test]
fn internet_ready_signal_fires_when_data_arrives() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_millis(150));
        socket.write_all(b"READY").unwrap();
        thread::sleep(Duration::from_millis(500));
    });

    let dir = temp_dir("tcpsignal");
    let config = dir.join("computer.yaml");
    fs::write(&config, base_config_with_tcp(None, true)).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        format!(
            r#"local component = require("component")
local computer = require("computer")
local socket = assert(component.internet.connect("127.0.0.1", {port}))
local deadline = computer.uptime() + 5
while not socket.finishConnect() do
  if computer.uptime() > deadline then error("connect timeout") end
  os.sleep(0.01)
end
local id = socket.id()
local found = false
deadline = computer.uptime() + 5
while computer.uptime() < deadline do
  local name, arg = computer.pullSignal(1)
  if name == "internet_ready" and arg == id then
    found = true
    break
  end
end
print("READY_SIGNAL:" .. tostring(found))
print("READY_DATA:" .. tostring(socket.read(64)))
socket.close()
require("computer").shutdown()"#,
            port = addr.port()
        ),
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &[]);
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(stdout.contains("READY_SIGNAL:true"), "stdout: {stdout}");
    assert!(stdout.contains("READY_DATA:READY"), "stdout: {stdout}");
}

#[test]
fn missing_root_filesystem_fails() {
    let dir = temp_dir("noroot");
    let config = dir.join("computer.yaml");
    fs::write(
        &config,
        "filesystems:\n  - label: home\n    path: builtin\n    mount: /home\n    readonly: false\n\
         run:\n  terminateDelay: 0\n",
    )
    .unwrap();

    let output = run_ocplay(&config, None, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("no root filesystem"), "stderr: {stderr}");
}

#[test]
fn script_receives_cli_arguments() {
    let dir = temp_dir("args");
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let config = dir.join("computer.yaml");
    fs::write(&config, base_config(Some(&out))).unwrap();
    let script = dir.join("script.lua");
    fs::write(
        &script,
        r#"local args = { ... }
local f = assert(io.open("/out/args.txt", "w"))
for i, value in ipairs(args) do
  f:write(i .. "=" .. value .. "\n")
end
f:close()
require("computer").shutdown()"#,
    )
    .unwrap();

    let output = run_ocplay(&config, Some(&script), &["alpha", "beta gamma", "quo\"te"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written = fs::read_to_string(out.join("args.txt")).unwrap();
    assert_eq!(written, "1=alpha\n2=beta gamma\n3=quo\"te\n");
}

#[test]
fn llm_fetches_reference_from_the_url() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = socket.read(&mut request);
        let body = "# ocplay — complete usage reference\n\n--interactive terminateDelay";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket.write_all(response.as_bytes()).unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_ocplay"))
        .arg("--llm")
        .env("OCPLAY_LLM_URL", format!("http://{addr}/llm.md"))
        .output()
        .expect("failed to run ocplay");
    server.join().unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("complete usage reference"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("--interactive"), "stdout: {stdout}");
}

#[test]
fn llm_reports_fetch_failure_without_a_config() {
    let output = Command::new(env!("CARGO_BIN_EXE_ocplay"))
        .arg("--llm")
        .env("OCPLAY_LLM_URL", "http://127.0.0.1:1/llm.md")
        .output()
        .expect("failed to run ocplay");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("could not fetch"), "stderr: {stderr}");
}
