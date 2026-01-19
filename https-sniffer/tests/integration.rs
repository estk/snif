//! Integration tests for https-sniffer
//!
//! Run on Linux VM: limactl shell snif cargo test --test integration

use anyhow::{Context, Result};
use regex::Regex;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

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
            std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "/tmp/target-https-sniffer".into());

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

        let binary_path = format!("{}/debug/https-sniffer", cargo_target_dir);

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
    async fn stop(mut self) -> Vec<String> {
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

        self.collected
    }

    /// Check if output contains a pattern
    fn contains(&self, pattern: &str) -> bool {
        self.collected.iter().any(|line| line.contains(pattern))
    }

    /// Count occurrences of a pattern
    fn count(&self, pattern: &str) -> usize {
        self.collected
            .iter()
            .filter(|line| line.contains(pattern))
            .count()
    }

    /// Check if output matches a regex
    fn matches(&self, pattern: &Regex) -> bool {
        self.collected.iter().any(|line| pattern.is_match(line))
    }

    /// Print collected output for debugging
    #[allow(dead_code)]
    fn debug_output(&self) {
        eprintln!("=== Sniffer Output ({} lines) ===", self.collected.len());
        for line in &self.collected {
            eprintln!("{}", line);
        }
        eprintln!("=== End Output ===");
    }
}

#[tokio::test]
async fn test_http1_get_request() {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    // Make HTTP/1.1 GET request using curl
    curl(&["-s", "--http1.1", "http://httpbin.org/get"]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    let contains = |p: &str| output.iter().any(|l| l.contains(p));

    assert!(contains("HTTP/1.1 Exchange"), "HTTP/1.1 exchange not captured");
    assert!(contains("GET /get"), "GET method and path not captured");
    assert!(contains("200 OK"), "200 OK response not captured");
}

#[tokio::test]
async fn test_http1_post_request() {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    // Make HTTP/1.1 POST request using curl
    curl(&[
        "-s", "--http1.1", "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d", r#"{"test":"data"}"#,
        "http://httpbin.org/post"
    ]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    let contains = |p: &str| output.iter().any(|l| l.contains(p));

    assert!(contains("HTTP/1.1 Exchange"), "HTTP/1.1 POST exchange not captured");
    assert!(contains("POST /post"), "POST method and path not captured");
}

#[tokio::test]
async fn test_http1_latency() {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    curl(&["-s", "--http1.1", "http://httpbin.org/get"]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    // Check latency is measured and > 0ms
    let latency_re = Regex::new(r"Latency: [1-9][0-9]*\.[0-9]+ms").unwrap();
    let has_latency = output.iter().any(|l| latency_re.is_match(l));

    assert!(has_latency, "Latency > 0ms not measured");
}

#[tokio::test]
async fn test_http2_https_request() {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    // Make HTTPS request (curl uses HTTP/2 by default for HTTPS)
    curl(&["-s", "https://httpbin.org/get"]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    let contains = |p: &str| output.iter().any(|l| l.contains(p));

    assert!(contains("HTTP/2 Exchange"), "HTTP/2 exchange not captured");
    assert!(contains("GET /get"), "GET method and path not captured via HPACK");
    assert!(contains("200 OK"), "200 OK response not captured");
}

#[tokio::test]
async fn test_ssl_handshake_events() {
    let mut sniffer = Sniffer::start(&["--raw"]).await.unwrap();

    curl(&["-s", "https://httpbin.org/get"]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    let contains = |p: &str| output.iter().any(|l| l.contains(p));

    assert!(contains("SSL Handshake"), "SSL handshake event not captured");
    assert!(contains("Duration:"), "Handshake duration not captured");
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

    let count = output.iter().filter(|l| l.contains("HTTP/1.1 Exchange")).count();

    assert!(count >= 3, "Expected at least 3 exchanges, got {}", count);
}

#[tokio::test]
async fn test_raw_socket_events() {
    let mut sniffer = Sniffer::start(&["--raw"]).await.unwrap();

    curl(&["-s", "--http1.1", "http://httpbin.org/get"]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    let contains = |p: &str| output.iter().any(|l| l.contains(p));

    assert!(contains("Kind: Socket Write"), "Socket write event not captured");
    assert!(contains("Kind: Socket Read"), "Socket read event not captured");
}

#[tokio::test]
async fn test_response_body_capture() {
    let mut sniffer = Sniffer::start(&["--collate"]).await.unwrap();

    curl(&["-s", "--http1.1", "http://httpbin.org/ip"]).await.unwrap();

    sniffer.collect_for(Duration::from_secs(2)).await;
    let output = sniffer.stop().await;

    let contains = |p: &str| output.iter().any(|l| l.contains(p));

    assert!(contains("\"origin\""), "Response body JSON not captured");
}
