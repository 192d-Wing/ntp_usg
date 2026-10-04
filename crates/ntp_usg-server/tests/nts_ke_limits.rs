// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTS-KE server admission control and per-connection deadline (#19).
//!
//! These tests drive the server with raw TCP connections that never start a
//! TLS handshake, which is exactly what a slowloris-style attacker does. No
//! certificate validation is involved so a self-signed cert is sufficient.

#![cfg(feature = "nts")]

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ntp_server::nts_ke_server::{NtsKeServer, NtsKeServerConfig};
use ntp_server::nts_server_common::MasterKeyStore;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

fn test_config() -> NtsKeServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    NtsKeServerConfig::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap()
}

/// Bind an ephemeral port so the server has a unique address, then release it.
async fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

async fn spawn_server(mut config: NtsKeServerConfig) -> SocketAddr {
    let addr = free_addr().await;
    config.listen_addr = addr.to_string();
    let key_store = Arc::new(RwLock::new(MasterKeyStore::new(Duration::from_secs(3600))));
    let server = NtsKeServer::new(config, key_store).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    wait_for_listener(addr).await
}

/// Same as [`spawn_server`] but runs the smol-runtime NTS-KE server on a
/// dedicated thread; the test body stays on tokio and only talks TCP.
#[cfg(feature = "nts-smol")]
async fn spawn_smol_server(mut config: NtsKeServerConfig) -> SocketAddr {
    use ntp_server::smol_nts_ke_server::NtsKeServer as SmolNtsKeServer;
    let addr = free_addr().await;
    config.listen_addr = addr.to_string();
    let key_store = Arc::new(RwLock::new(MasterKeyStore::new(Duration::from_secs(3600))));
    let server = SmolNtsKeServer::new(config, key_store).unwrap();
    std::thread::spawn(move || {
        let _ = smol::block_on(server.run());
    });
    wait_for_listener(addr).await
}

async fn wait_for_listener(addr: SocketAddr) -> SocketAddr {
    // Wait for the listener to come up.
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            // That probe connection consumed nothing; it is dropped here and
            // the server releases its slot when it notices the close.
            tokio::time::sleep(Duration::from_millis(50)).await;
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("NTS-KE server did not start");
}

/// Outcome of waiting on a connection the client never writes to.
#[derive(Debug, PartialEq)]
enum Fate {
    /// Server closed the connection (read returned EOF).
    Closed,
    /// Connection still open after the wait.
    Open,
}

async fn fate_within(stream: &mut TcpStream, wait: Duration) -> Fate {
    let mut buf = [0u8; 1];
    match tokio::time::timeout(wait, stream.read(&mut buf)).await {
        Ok(Ok(0)) => Fate::Closed,
        Ok(Ok(_)) => panic!("server sent data to a client that never spoke TLS"),
        // A reset also means the server hung up.
        Ok(Err(_)) => Fate::Closed,
        Err(_) => Fate::Open,
    }
}

#[tokio::test]
async fn excess_connections_are_refused_before_tls() {
    let mut config = test_config();
    config.max_connections = 2;
    config.max_connections_per_ip = 0;
    config.connection_timeout = Duration::from_secs(30);
    let addr = spawn_server(config).await;

    let mut c1 = TcpStream::connect(addr).await.unwrap();
    let mut c2 = TcpStream::connect(addr).await.unwrap();
    // Give the accept loop time to admit both.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c3 = TcpStream::connect(addr).await.unwrap();

    // The third connection is closed by the server without any handshake.
    assert_eq!(
        fate_within(&mut c3, Duration::from_secs(2)).await,
        Fate::Closed
    );
    // The first two are still being served (waiting for ClientHello).
    assert_eq!(
        fate_within(&mut c1, Duration::from_millis(300)).await,
        Fate::Open
    );
    assert_eq!(
        fate_within(&mut c2, Duration::from_millis(300)).await,
        Fate::Open
    );

    // Releasing one frees a slot for a newcomer.
    drop(c1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut c4 = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        fate_within(&mut c4, Duration::from_millis(500)).await,
        Fate::Open
    );
}

#[tokio::test]
async fn per_ip_cap_is_enforced() {
    let mut config = test_config();
    config.max_connections = 100;
    config.max_connections_per_ip = 1;
    config.connection_timeout = Duration::from_secs(30);
    let addr = spawn_server(config).await;

    let mut c1 = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c2 = TcpStream::connect(addr).await.unwrap();

    assert_eq!(
        fate_within(&mut c2, Duration::from_secs(2)).await,
        Fate::Closed
    );
    assert_eq!(
        fate_within(&mut c1, Duration::from_millis(300)).await,
        Fate::Open
    );
}

#[tokio::test]
async fn stalled_connection_is_closed_at_deadline_and_slot_freed() {
    let mut config = test_config();
    config.max_connections = 1;
    config.max_connections_per_ip = 0;
    config.connection_timeout = Duration::from_millis(400);
    let addr = spawn_server(config).await;
    check_deadline_frees_slot(addr).await;
}

#[cfg(feature = "nts-smol")]
#[tokio::test]
async fn smol_excess_connections_are_refused_before_tls() {
    let mut config = test_config();
    config.max_connections = 1;
    config.max_connections_per_ip = 0;
    config.connection_timeout = Duration::from_secs(30);
    let addr = spawn_smol_server(config).await;

    let mut c1 = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c2 = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        fate_within(&mut c2, Duration::from_secs(2)).await,
        Fate::Closed
    );
    assert_eq!(
        fate_within(&mut c1, Duration::from_millis(300)).await,
        Fate::Open
    );
}

#[cfg(feature = "nts-smol")]
#[tokio::test]
async fn smol_stalled_connection_is_closed_at_deadline_and_slot_freed() {
    let mut config = test_config();
    config.max_connections = 1;
    config.max_connections_per_ip = 0;
    config.connection_timeout = Duration::from_millis(400);
    let addr = spawn_smol_server(config).await;
    check_deadline_frees_slot(addr).await;
}

async fn check_deadline_frees_slot(addr: SocketAddr) {
    // A client that connects and never sends a ClientHello.
    let mut slow = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        fate_within(&mut slow, Duration::from_millis(150)).await,
        Fate::Open,
        "connection must not be cut before the deadline"
    );
    assert_eq!(
        fate_within(&mut slow, Duration::from_secs(2)).await,
        Fate::Closed,
        "stalled connection must be closed once the deadline passes"
    );

    // The slot held by the stalled connection is released on timeout.
    let mut next = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        fate_within(&mut next, Duration::from_millis(200)).await,
        Fate::Open
    );
}
