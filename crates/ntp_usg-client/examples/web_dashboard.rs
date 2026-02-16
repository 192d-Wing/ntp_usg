// Web dashboard example demonstrating:
// - Real-time NTP monitoring with WebSocket updates
// - HTTP API for current sync state
// - HTML/JavaScript dashboard with charts
// - Production-ready metrics endpoint

use ntp_client::client::NtpClient;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 NTP Web Dashboard");
    println!("===================\n");

    // Configure NTP client
    println!("⚙️  Configuring NTP client...");
    let (client, state_rx) = NtpClient::builder()
        .server("time.nist.gov:123")
        .server("time.cloudflare.com:123")
        .server("time.google.com:123")
        .min_poll(6) // 64 seconds
        .max_poll(10) // 1024 seconds
        .build()
        .await?;

    println!("✅ NTP client configured\n");

    // Shared state for web server
    let state = Arc::new(RwLock::new(DashboardState::default()));
    let state_clone = Arc::clone(&state);

    // Spawn NTP client task
    tokio::spawn(client.run());

    // Spawn state update task
    tokio::spawn(async move {
        update_dashboard_state(state_rx, state_clone).await;
    });

    // Start web server
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    println!("🚀 Web dashboard starting at http://{}/ \n", addr);
    println!("📊 Metrics endpoint: http://{}/metrics", addr);
    println!("🔗 API endpoint: http://{}/api/state\n", addr);

    run_web_server(addr, state).await?;

    Ok(())
}

#[derive(Clone, Debug)]
struct DashboardState {
    offset: f64,
    delay: f64,
    jitter: f64,
    last_update: Option<std::time::Instant>,
    update_count: u64,
    history: Vec<HistoryPoint>,
}

#[derive(Clone, Debug)]
struct HistoryPoint {
    timestamp: u64,
    offset: f64,
    delay: f64,
    jitter: f64,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            offset: 0.0,
            delay: 0.0,
            jitter: 0.0,
            last_update: None,
            update_count: 0,
            history: Vec::new(),
        }
    }
}

async fn update_dashboard_state(
    mut state_rx: tokio::sync::watch::Receiver<ntp_client::client_common::NtpSyncState>,
    dashboard_state: Arc<RwLock<DashboardState>>,
) {
    while state_rx.changed().await.is_ok() {
        let ntp_state = state_rx.borrow().clone();
        let mut state = dashboard_state.write().await;

        state.offset = ntp_state.offset;
        state.delay = ntp_state.delay;
        state.jitter = ntp_state.jitter;
        state.last_update = Some(std::time::Instant::now());
        state.update_count += 1;

        // Keep last 100 data points for chart
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        state.history.push(HistoryPoint {
            timestamp,
            offset: ntp_state.offset,
            delay: ntp_state.delay,
            jitter: ntp_state.jitter,
        });

        if state.history.len() > 100 {
            state.history.remove(0);
        }

        println!(
            "[Dashboard] Update #{}: offset={:.6}s, delay={:.6}s, jitter={:.6}s",
            state.update_count, ntp_state.offset, ntp_state.delay, ntp_state.jitter
        );
    }
}

async fn run_web_server(
    addr: SocketAddr,
    state: Arc<RwLock<DashboardState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr).await?;
    println!("✅ Web server listening on {}\n", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                eprintln!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    state: Arc<RwLock<DashboardState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = [0; 1024];
    let mut stream = stream;

    let n = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..n]);

    // Parse HTTP request line
    let request_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Ok(());
    }

    let path = parts[1];

    match path {
        "/" => {
            // Serve HTML dashboard
            let html = generate_dashboard_html();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                html.len(),
                html
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/api/state" => {
            // JSON API endpoint
            let state = state.read().await;
            let json = serde_json::json!({
                "offset": state.offset,
                "delay": state.delay,
                "jitter": state.jitter,
                "update_count": state.update_count,
                "last_update": state.last_update.map(|t| t.elapsed().as_secs()),
                "history": state.history.iter().map(|p| {
                    serde_json::json!({
                        "timestamp": p.timestamp,
                        "offset": p.offset,
                        "delay": p.delay,
                        "jitter": p.jitter,
                    })
                }).collect::<Vec<_>>(),
            });

            let body = serde_json::to_string_pretty(&json)?;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/metrics" => {
            // Prometheus-compatible metrics endpoint
            let state = state.read().await;
            let metrics = format!(
                "# HELP ntp_offset_seconds Current clock offset in seconds\n\
                 # TYPE ntp_offset_seconds gauge\n\
                 ntp_offset_seconds {:.6}\n\
                 # HELP ntp_delay_seconds Current round-trip delay in seconds\n\
                 # TYPE ntp_delay_seconds gauge\n\
                 ntp_delay_seconds {:.6}\n\
                 # HELP ntp_jitter_seconds Current jitter in seconds\n\
                 # TYPE ntp_jitter_seconds gauge\n\
                 ntp_jitter_seconds {:.6}\n\
                 # HELP ntp_updates_total Total number of NTP updates\n\
                 # TYPE ntp_updates_total counter\n\
                 ntp_updates_total {}\n",
                state.offset, state.delay, state.jitter, state.update_count
            );

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                metrics.len(),
                metrics
            );
            stream.write_all(response.as_bytes()).await?;
        }
        _ => {
            // 404 Not Found
            let body = "404 Not Found";
            let response = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}

fn generate_dashboard_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NTP Monitoring Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1 {
            color: white;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.2s;
        }
        .metric-card:hover {
            transform: translateY(-5px);
        }
        .metric-label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .metric-unit {
            font-size: 0.4em;
            color: #999;
            font-weight: normal;
        }
        .status {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        .status-healthy { background: #10b981; }
        .status-warning { background: #f59e0b; }
        .status-error { background: #ef4444; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .chart-container {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            height: 400px;
        }
        .footer {
            text-align: center;
            color: white;
            margin-top: 30px;
            font-size: 0.9em;
        }
        .api-links {
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 15px;
            margin-top: 20px;
            text-align: center;
        }
        .api-links a {
            color: white;
            text-decoration: none;
            margin: 0 15px;
            padding: 8px 16px;
            background: rgba(255,255,255,0.2);
            border-radius: 6px;
            transition: background 0.2s;
        }
        .api-links a:hover {
            background: rgba(255,255,255,0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🕐 NTP Monitoring Dashboard</h1>

        <div class="status" id="status">
            <span class="status-indicator status-healthy"></span>
            <strong>Synchronizing</strong> - Last update: <span id="last-update">waiting...</span>
        </div>

        <div class="metrics">
            <div class="metric-card">
                <div class="metric-label">Clock Offset</div>
                <div class="metric-value" id="offset">0.000000<span class="metric-unit">s</span></div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Round-Trip Delay</div>
                <div class="metric-value" id="delay">0.000000<span class="metric-unit">s</span></div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Jitter</div>
                <div class="metric-value" id="jitter">0.000000<span class="metric-unit">s</span></div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Updates</div>
                <div class="metric-value" id="updates">0</div>
            </div>
        </div>

        <div class="chart-container">
            <canvas id="chart"></canvas>
        </div>

        <div class="api-links">
            <a href="/api/state" target="_blank">📊 JSON API</a>
            <a href="/metrics" target="_blank">📈 Metrics</a>
        </div>

        <div class="footer">
            NTP USG v3.1.0 | Powered by Rust 🦀
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Chart setup
        const ctx = document.getElementById('chart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Offset (ms)',
                    data: [],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.3
                }, {
                    label: 'Delay (ms)',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'NTP Metrics Over Time' }
                },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Milliseconds' } }
                }
            }
        });

        // Update dashboard
        async function updateDashboard() {
            try {
                const response = await fetch('/api/state');
                const data = await response.json();

                // Update metric cards
                document.getElementById('offset').innerHTML =
                    `${data.offset.toFixed(6)}<span class="metric-unit">s</span>`;
                document.getElementById('delay').innerHTML =
                    `${data.delay.toFixed(6)}<span class="metric-unit">s</span>`;
                document.getElementById('jitter').innerHTML =
                    `${data.jitter.toFixed(6)}<span class="metric-unit">s</span>`;
                document.getElementById('updates').textContent = data.update_count;
                document.getElementById('last-update').textContent =
                    data.last_update ? `${data.last_update}s ago` : 'never';

                // Update status indicator
                const offsetMs = Math.abs(data.offset * 1000);
                const statusEl = document.querySelector('.status-indicator');
                const statusText = document.querySelector('.status strong');

                if (offsetMs < 10 && data.jitter < 0.01) {
                    statusEl.className = 'status-indicator status-healthy';
                    statusText.textContent = 'Excellent';
                } else if (offsetMs < 100 && data.jitter < 0.05) {
                    statusEl.className = 'status-indicator status-healthy';
                    statusText.textContent = 'Good';
                } else if (offsetMs < 500) {
                    statusEl.className = 'status-indicator status-warning';
                    statusText.textContent = 'Degraded';
                } else {
                    statusEl.className = 'status-indicator status-error';
                    statusText.textContent = 'Poor';
                }

                // Update chart with last 50 points
                const history = data.history.slice(-50);
                chart.data.labels = history.map(h => {
                    const date = new Date(h.timestamp * 1000);
                    return date.toLocaleTimeString();
                });
                chart.data.datasets[0].data = history.map(h => h.offset * 1000);
                chart.data.datasets[1].data = history.map(h => h.delay * 1000);
                chart.update();

            } catch (error) {
                console.error('Failed to update dashboard:', error);
            }
        }

        // Update every 2 seconds
        updateDashboard();
        setInterval(updateDashboard, 2000);
    </script>
</body>
</html>"#.to_string()
}
