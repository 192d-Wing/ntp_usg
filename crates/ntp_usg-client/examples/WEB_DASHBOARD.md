# NTP Web Dashboard

A real-time web-based monitoring dashboard for NTP synchronization.

## Features

- **Real-time Monitoring**: Live updates every 2 seconds
- **Visual Charts**: Interactive Chart.js graphs showing offset and delay trends
- **Health Indicators**: Color-coded status based on sync quality
- **Multiple Endpoints**:
  - `/` - HTML dashboard with charts
  - `/api/state` - JSON API for programmatic access
  - `/metrics` - Prometheus-compatible metrics

## Quick Start

```bash
cargo run -p ntp_usg-client --example web_dashboard --features ntp_usg-client/tokio
```

Then open your browser to: **http://127.0.0.1:8080/**

## Screenshots

### Main Dashboard
```
┌──────────────────────────────────────────┐
│    🕐 NTP Monitoring Dashboard          │
├──────────────────────────────────────────┤
│ 🟢 Excellent - Last update: 2s ago       │
├──────────────────────────────────────────┤
│  Clock Offset  │  Delay  │  Jitter  │...│
│   0.005466s    │ 0.019s  │ 0.000s   │...│
├──────────────────────────────────────────┤
│          Chart: Offset & Delay           │
│              (last 50 points)            │
└──────────────────────────────────────────┘
```

## Endpoints

### 1. HTML Dashboard: `/`

Interactive web interface with:
- Real-time metric cards (offset, delay, jitter, update count)
- Health status indicator with color-coded alerts
- Time-series chart showing last 50 data points
- Auto-refresh every 2 seconds

**Browser Requirements**: Modern browser with JavaScript enabled

### 2. JSON API: `/api/state`

Returns current NTP synchronization state as JSON.

**Example Request:**
```bash
curl http://127.0.0.1:8080/api/state
```

**Example Response:**
```json
{
  "offset": 0.005466,
  "delay": 0.019873,
  "jitter": 0.000000,
  "update_count": 15,
  "last_update": 3,
  "history": [
    {
      "timestamp": 1707962345,
      "offset": 0.005466,
      "delay": 0.019873,
      "jitter": 0.000000
    }
  ]
}
```

**Fields:**
- `offset` (float): Clock offset in seconds
- `delay` (float): Round-trip delay in seconds
- `jitter` (float): Jitter (dispersion) in seconds
- `update_count` (int): Total number of NTP updates
- `last_update` (int|null): Seconds since last update
- `history` (array): Last 100 data points with timestamps

### 3. Prometheus Metrics: `/metrics`

Prometheus-compatible metrics endpoint for monitoring systems.

**Example Request:**
```bash
curl http://127.0.0.1:8080/metrics
```

**Example Response:**
```prometheus
# HELP ntp_offset_seconds Current clock offset in seconds
# TYPE ntp_offset_seconds gauge
ntp_offset_seconds 0.005466
# HELP ntp_delay_seconds Current round-trip delay in seconds
# TYPE ntp_delay_seconds gauge
ntp_delay_seconds 0.019873
# HELP ntp_jitter_seconds Current jitter in seconds
# TYPE ntp_jitter_seconds gauge
ntp_jitter_seconds 0.000000
# HELP ntp_updates_total Total number of NTP updates
# TYPE ntp_updates_total counter
ntp_updates_total 15
```

## Health Status Thresholds

| Status | Indicator | Offset | Jitter | Description |
|--------|-----------|--------|--------|-------------|
| 🟢 Excellent | Green | < 10ms | < 10ms | Optimal sync |
| 🟢 Good | Green | < 100ms | < 50ms | Normal operation |
| 🟡 Degraded | Yellow | < 500ms | Any | Acceptable but suboptimal |
| 🔴 Poor | Red | ≥ 500ms | Any | Sync issues |

## Configuration

### NTP Servers

The example uses three public NTP servers by default:
- time.nist.gov (US Government)
- time.cloudflare.com (Global CDN)
- time.google.com (Global infrastructure)

**To customize servers**, edit the example code:

```rust
let (client, state_rx) = NtpClient::builder()
    .server("your-ntp-server.com:123")
    .server("backup-server.com:123")
    .min_poll(6)   // 64 seconds
    .max_poll(10)  // 1024 seconds
    .build()
    .await?;
```

### Port Configuration

Default port: `8080`

**To change the port**, edit:

```rust
let addr: SocketAddr = "127.0.0.1:3000".parse()?;  // Use port 3000
```

### Update Interval

The NTP client updates based on adaptive polling (64-1024 seconds by default).

The web dashboard refreshes the UI every 2 seconds to display latest data.

## Integration Examples

### Prometheus Scraping

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'ntp_monitor'
    scrape_interval: 30s
    static_configs:
      - targets: ['localhost:8080']
```

### Grafana Dashboard

1. Add Prometheus as data source
2. Create dashboard with queries:
   ```promql
   # Offset over time
   ntp_offset_seconds

   # Delay over time
   ntp_delay_seconds

   # Update rate
   rate(ntp_updates_total[5m])
   ```

### Custom JavaScript Client

```javascript
async function monitorNTP() {
    const response = await fetch('http://localhost:8080/api/state');
    const data = await response.json();

    if (Math.abs(data.offset) > 0.1) {
        console.warn('High clock offset detected:', data.offset);
    }

    console.log(`Offset: ${data.offset}s, Delay: ${data.delay}s`);
}

setInterval(monitorNTP, 5000);  // Check every 5 seconds
```

### curl Monitoring Script

```bash
#!/bin/bash
# Simple monitoring script

while true; do
    curl -s http://localhost:8080/api/state | jq -r '
        "Offset: \(.offset)s | Delay: \(.delay)s | Updates: \(.update_count)"
    '
    sleep 10
done
```

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/ntp-dashboard.service`:

```ini
[Unit]
Description=NTP Monitoring Dashboard
After=network.target

[Service]
Type=simple
User=ntpuser
WorkingDirectory=/opt/ntp-dashboard
ExecStart=/opt/ntp-dashboard/web_dashboard
Restart=on-failure
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable ntp-dashboard
sudo systemctl start ntp-dashboard
```

### Reverse Proxy (nginx)

```nginx
server {
    listen 80;
    server_name ntp-monitor.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Docker Deployment

```dockerfile
FROM rust:1-slim as builder
WORKDIR /build
COPY . .
RUN cargo build --release --example web_dashboard --features ntp_usg-client/tokio

FROM debian:trixie-slim
COPY --from=builder /build/target/release/examples/web_dashboard /usr/local/bin/
EXPOSE 8080
CMD ["web_dashboard"]
```

Build and run:
```bash
docker build -t ntp-dashboard .
docker run -p 8080:8080 ntp-dashboard
```

## Security Considerations

### Network Exposure

⚠️ **Default**: Binds to `127.0.0.1` (localhost only)

For remote access, change to `0.0.0.0`:
```rust
let addr: SocketAddr = "0.0.0.0:8080".parse()?;
```

**Important**: When exposing publicly:
- Use a reverse proxy (nginx, Caddy) with TLS
- Implement authentication (Basic Auth, OAuth, etc.)
- Enable rate limiting
- Consider firewall rules

### Authentication

The example does not include authentication. For production:

1. **Basic Auth** (nginx):
   ```nginx
   location / {
       auth_basic "NTP Dashboard";
       auth_basic_user_file /etc/nginx/.htpasswd;
       proxy_pass http://127.0.0.1:8080;
   }
   ```

2. **API Tokens**: Add token validation to `/api/state`

3. **OAuth/SSO**: Use a reverse proxy with OAuth support

## Troubleshooting

### Dashboard not loading

**Check if server is running:**
```bash
curl http://127.0.0.1:8080/metrics
```

**Check port availability:**
```bash
lsof -i :8080
```

### No data showing

- Wait 64 seconds for first NTP update (min_poll interval)
- Check console output for NTP errors
- Verify NTP servers are reachable: `ntpdate -q time.nist.gov`

### High offset values

- System clock may be significantly wrong
- Check network latency: `ping time.nist.gov`
- Try different NTP servers
- Consider using NTS for authenticated time

### Chart not rendering

- Check browser console for JavaScript errors
- Verify Chart.js CDN is accessible
- Try hard refresh: Ctrl+Shift+R (Cmd+Shift+R on Mac)

## Performance

### Resource Usage

- **Memory**: ~2-5 MB (Rust binary + dashboard state)
- **CPU**: < 0.1% (mostly idle, periodic NTP polls)
- **Network**: ~1 KB every 64-1024 seconds (NTP queries)

### Scaling

The dashboard stores the last 100 data points in memory (~10 KB). This grows linearly with history size.

**For high-frequency monitoring** (many concurrent web clients):
- Use a reverse proxy with caching
- Store history in Redis/database
- Implement WebSocket for real-time updates

## Advanced Features

### Custom Metrics

Add custom metrics to the `/metrics` endpoint:

```rust
let metrics = format!(
    "{}# HELP ntp_custom_metric Your custom metric\n\
     # TYPE ntp_custom_metric gauge\n\
     ntp_custom_metric {}\n",
    metrics, custom_value
);
```

### Alerts

Implement alerting based on thresholds:

```rust
if state.offset.abs() > 0.5 {
    // Send alert (email, Slack, PagerDuty, etc.)
    eprintln!("ALERT: High offset detected: {:.3}s", state.offset);
}
```

### Database Logging

Store history in a database for long-term analysis:

```rust
// Example with SQLite
sqlx::query("INSERT INTO ntp_history (timestamp, offset, delay) VALUES (?, ?, ?)")
    .bind(timestamp)
    .bind(state.offset)
    .bind(state.delay)
    .execute(&pool)
    .await?;
```

## API Reference

### DashboardState Structure

```rust
struct DashboardState {
    offset: f64,           // Clock offset (seconds)
    delay: f64,            // Round-trip delay (seconds)
    jitter: f64,           // Jitter (seconds)
    last_update: Option<Instant>,  // Last update time
    update_count: u64,     // Total updates
    history: Vec<HistoryPoint>,    // Historical data (last 100)
}
```

### HistoryPoint Structure

```rust
struct HistoryPoint {
    timestamp: u64,   // Unix timestamp
    offset: f64,      // Offset at this time
    delay: f64,       // Delay at this time
    jitter: f64,      // Jitter at this time
}
```

## Related Examples

- [daemon.rs](daemon.rs) - Production daemon with systemd integration
- [multi_peer_deployment.rs](multi_peer_deployment.rs) - Multi-peer NTP configuration
- [continuous.rs](continuous.rs) - Basic continuous client

## Resources

- [Chart.js Documentation](https://www.chartjs.org/docs/)
- [Prometheus Metrics Format](https://prometheus.io/docs/instrumenting/exposition_formats/)
- [NTP Best Practices](https://www.ntp.org/documentation/4.2.8-series/prefer/)
- [RFC 5905: Network Time Protocol](https://www.rfc-editor.org/rfc/rfc5905.html)
