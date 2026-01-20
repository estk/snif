//! Integration tests for snif
//!
//! Run on Linux VM: limactl shell snif cargo test --test integration

use anyhow::{Context, Result};
use regex::Regex;
use rstest::rstest;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

/// A pattern that can match against a line of output
trait Pattern {
    fn matches_line(&self, line: &str) -> bool;
}

impl Pattern for &str {
    fn matches_line(&self, line: &str) -> bool {
        line.contains(*self)
    }
}

impl Pattern for Regex {
    fn matches_line(&self, line: &str) -> bool {
        self.is_match(line)
    }
}

/// Collected output from the sniffer with helper methods
struct Output(Vec<String>);

impl Output {
    /// Check if any line matches the pattern
    fn contains(&self, pattern: impl Pattern) -> bool {
        self.0.iter().any(|line| pattern.matches_line(line))
    }

    /// Count lines matching the pattern
    fn count(&self, pattern: impl Pattern) -> usize {
        self.0
            .iter()
            .filter(|line| pattern.matches_line(line))
            .count()
    }
}

/// Run curl command and wait for it to complete
async fn curl(args: &[&str]) -> Result<()> {
    let status = Command::new("curl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("curl failed");
    }
    Ok(())
}

/// A running sniffer process that captures output
struct Sniffer {
    child: Child,
    output_rx: mpsc::Receiver<String>,
    collected: Vec<String>,
}

impl Sniffer {
    /// Start the sniffer with the given arguments
    async fn start(args: &[&str]) -> Result<Self> {
        let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let cargo_target_dir =
            std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "/tmp/target-snif".into());

        // Build first
        let build_status = Command::new("cargo")
            .arg("build")
            .arg("--quiet")
            .current_dir(&project_dir)
            .env("CARGO_TARGET_DIR", &cargo_target_dir)
            .status()
            .await
            .context("Failed to run cargo build")?;

        if !build_status.success() {
            anyhow::bail!("cargo build failed");
        }

        let binary_path = format!("{}/debug/snif", cargo_target_dir);

        // Start sniffer with sudo
        let mut cmd = Command::new("sudo");
        cmd.arg("-E")
            .arg(&binary_path)
            .args(args)
            .current_dir(&project_dir)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn sniffer")?;

        // Capture stderr (where logs go)
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = mpsc::channel(1000);

        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(line).await;
            }
        });

        // Wait for sniffer to be ready
        tokio::time::sleep(Duration::from_secs(3)).await;

        Ok(Self {
            child,
            output_rx: rx,
            collected: Vec::new(),
        })
    }

    /// Collect output for a duration
    async fn collect_for(&mut self, duration: Duration) {
        let deadline = tokio::time::Instant::now() + duration;
        while tokio::time::Instant::now() < deadline {
            match timeout(Duration::from_millis(100), self.output_rx.recv()).await {
                Ok(Some(line)) => self.collected.push(line),
                Ok(None) => break,
                Err(_) => continue,
            }
        }
    }

    /// Drain any remaining output
    async fn drain(&mut self) {
        while let Ok(Some(line)) = timeout(Duration::from_millis(100), self.output_rx.recv()).await
        {
            self.collected.push(line);
        }
    }

    /// Stop the sniffer gracefully
    async fn stop(mut self) -> Output {
        // Send SIGINT
        if let Some(pid) = self.child.id() {
            let _ = Command::new("sudo")
                .args(["kill", "-INT", &pid.to_string()])
                .status()
                .await;
        }

        // Wait and drain remaining output
        tokio::time::sleep(Duration::from_secs(1)).await;
        self.drain().await;

        // Wait for process to exit
        let _ = timeout(Duration::from_secs(5), self.child.wait()).await;

        Output(self.collected)
    }
}

// ============================================================================
// HTTP request tests (parameterized)
// ============================================================================

#[rstest]
#[case::http1_get(
    &["-s", "--http1.1", "http://httpbin.org/get"],
    "HTTP/1.1 Exchange",
    "GET /get"
)]
#[case::http1_post(
    &["-s", "--http1.1", "-X", "POST", "-H", "Content-Type: application/json", "-d", r#"{"test":"data"}"#, "http://httpbin.org/post"],
    "HTTP/1.1 Exchange",
    "POST /post"
)]
#[case::http2_get(
    &["-s", "https://httpbin.org/get"],
    "HTTP/2 Exchange",
    "GET /get"
)]
#[tokio::test]
async fn test_http_request(
    #[case] curl_args: &[&str],
    #[case] expected_exchange: &str,
    #[case] expected_method_path: &str,
) {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    curl(curl_args).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    assert!(
        output.contains(expected_exchange),
        "{} exchange not captured",
        expected_exchange
    );
    assert!(
        output.contains(expected_method_path),
        "{} not captured",
        expected_method_path
    );
    assert!(output.contains("200 OK"), "200 OK response not captured");
}

#[tokio::test]
async fn test_http1_latency() {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    curl(&["-s", "--http1.1", "http://httpbin.org/get"])
        .await
        .unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    // Check latency is measured and > 0ms
    let latency_re = Regex::new(r"Latency: [1-9][0-9]*\.[0-9]+ms").unwrap();
    assert!(output.contains(latency_re), "Latency > 0ms not measured");
}

#[rstest]
#[case::ssl_handshake(&["--raw"], "SSL Handshake")]
#[case::handshake_duration(&["--raw"], "Duration:")]
#[tokio::test]
async fn test_ssl_events(#[case] sniffer_args: &[&str], #[case] expected_pattern: &str) {
    let mut sniffer = Sniffer::start(sniffer_args).await.unwrap();

    curl(&["-s", "https://httpbin.org/get"]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    assert!(
        output.contains(expected_pattern),
        "{} not captured",
        expected_pattern
    );
}

#[tokio::test]
async fn test_multiple_concurrent_requests() {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    // Make 3 concurrent requests using curl
    let (r1, r2, r3) = tokio::join!(
        curl(&["-s", "--http1.1", "http://httpbin.org/get"]),
        curl(&["-s", "--http1.1", "http://httpbin.org/ip"]),
        curl(&["-s", "--http1.1", "http://httpbin.org/headers"]),
    );
    let _ = (r1, r2, r3);

    sniffer.collect_for(Duration::from_secs(3)).await;
    let output = sniffer.stop().await;

    let count = output.count("HTTP/1.1 Exchange");
    assert!(count >= 3, "Expected at least 3 exchanges, got {}", count);
}

#[rstest]
#[case::socket_write("Kind: Socket Write")]
#[case::socket_read("Kind: Socket Read")]
#[tokio::test]
async fn test_raw_socket_events(#[case] expected_pattern: &str) {
    let mut sniffer = Sniffer::start(&["--raw"]).await.unwrap();

    curl(&["-s", "--http1.1", "http://httpbin.org/get"])
        .await
        .unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    assert!(
        output.contains(expected_pattern),
        "{} not captured",
        expected_pattern
    );
}

#[tokio::test]
async fn test_response_body_capture() {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    curl(&["-s", "--http1.1", "http://httpbin.org/ip"])
        .await
        .unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    assert!(
        output.contains("\"origin\""),
        "Response body JSON not captured"
    );
}

// ============================================================================
// Filter tests (local-port and direction)
// ============================================================================

/// A simple local HTTP server for testing filters
struct LocalServer {
    port: u16,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl LocalServer {
    /// Start a local HTTP server on the given port
    async fn start(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .context("Failed to bind local server")?;

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        if let Ok((mut socket, _)) = accept_result {
                            tokio::spawn(async move {
                                let mut buf = [0u8; 1024];
                                // Read request
                                let _ = socket.read(&mut buf).await;

                                // Send simple HTTP response
                                let response = "HTTP/1.1 200 OK\r\n\
                                    Content-Type: text/plain\r\n\
                                    Content-Length: 13\r\n\
                                    Connection: close\r\n\
                                    \r\n\
                                    Hello, World!";
                                let _ = socket.write_all(response.as_bytes()).await;
                            });
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(Self {
            port,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }
    }
}

#[rstest]
#[case::local_port_matches(18080, &["--raw", "--port", "local:18080"], 2, ">=")]
#[case::local_port_filter(18081, &["--raw", "--port", "local:18081"], 1, ">=")]
#[case::direction_incoming(18082, &["--raw", "--port", "local:18082", "--direction", "incoming"], 1, ">=")]
#[case::direction_outgoing(18083, &["--raw", "--port", "local:18083", "--direction", "outgoing"], 1, "==")]
#[tokio::test]
async fn test_filter(
    #[case] port: u16,
    #[case] sniffer_args: &[&str],
    #[case] expected_count: usize,
    #[case] comparison: &str,
) {
    let server = LocalServer::start(port).await.unwrap();
    let mut sniffer = Sniffer::start(sniffer_args).await.unwrap();

    curl(&["-s", "--http1.1", &server.url()]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    let socket_event_count = output.count("Kind: Socket");

    match comparison {
        ">=" => assert!(
            socket_event_count >= expected_count,
            "Expected >= {} socket events, got {}",
            expected_count,
            socket_event_count
        ),
        "==" => assert!(
            socket_event_count == expected_count,
            "Expected == {} socket events, got {}",
            expected_count,
            socket_event_count
        ),
        _ => panic!("Unknown comparison: {}", comparison),
    }
}
