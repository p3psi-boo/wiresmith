mod args;

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use args::{ApiServerArgs, Command, RunArgs};
use axum::{
    extract::{Path, State},
    routing::get, // Removed put from here
    Json, Router,
};
use clap::Parser;
use serde_json::json;
use tokio::time::{interval, sleep};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace};

use wiresmith::{
    consul::ConsulClient, networkd::NetworkdConfiguration, wireguard::WgPeer, CONSUL_TTL,
};

// Shared state for the KV store
type KvStore = Arc<Mutex<HashMap<String, String>>>;

#[derive(Clone)]
struct ApiState {
    kv_store: KvStore,
    datacenter_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Spawn a task to cancel us if we receive a SIGINT.
    let top_level_token = CancellationToken::new();
    tokio::spawn({
        let token = top_level_token.clone();
        async move {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to listen for SIGINT");
            info!("Received SIGINT, triggering shutdown");
            token.cancel();
        }
    });

    let cli_args = args::CliArgs::parse();

    match cli_args.command {
        Command::Run(run_args) => {
            if run_args.verbose == 2 {
                tracing_subscriber::fmt()
                    .with_env_filter("wiresmith=trace")
                    .init();
            } else if run_args.verbose == 1 {
                tracing_subscriber::fmt()
                    .with_env_filter("wiresmith=debug")
                    .init();
            } else {
                tracing_subscriber::fmt()
                    .with_env_filter("wiresmith=info")
                    .init();
            };

            if let Some(address) = run_args.address {
                ensure!(
                    run_args.network.contains(&address),
                    "Address {address} is not part of network {}",
                    run_args.network
                );
            }

            let consul_client = ConsulClient::new(
                run_args.consul_address.clone(),
                &run_args.consul_prefix,
                run_args.consul_token.as_deref(),
            )?;

            let endpoint_address = if let Some(endpoint_address) = &run_args.endpoint_address {
                endpoint_address.clone()
            } else if let Some(endpoint_interface) = &run_args.endpoint_interface {
                // Find suitable IP on provided interface.
                endpoint_interface
                    .ips
                    .first()
                    .context("No IPs on interface")?
                    .ip()
                    .to_string()
            } else {
                unreachable!("Should have been handled by arg parsing");
            };

            info!("Getting existing peers from Consul");
            let peers = consul_client.get_peers().await?;
            if peers.is_empty() {
                info!("No existing peers found in Consul");
            } else {
                info!("Found {} existing peer(s) in Consul", peers.len());
                debug!("Existing peers:\n{:#?}", peers);
            }

            // Check whether we can find and parse an existing config.
            let networkd_config = if let Ok(config) =
                NetworkdConfiguration::from_config(&run_args.networkd_dir, &run_args.wg_interface)
                    .await
            {
                info!("Successfully loading existing systemd-networkd config");
                config
            } else {
                info!("No existing WireGuard configuration found on system, creating a new one");

                // If we can't find or parse an existing config, we'll just generate a new one.
                let networkd_config = NetworkdConfiguration::new(
                    run_args.address,
                    run_args.network,
                    run_args.wg_port,
                    &run_args.wg_interface,
                    peers,
                    run_args.ipv6_only,
                )?;
                networkd_config
                    .write_config(&run_args.networkd_dir, run_args.keepalive)
                    .await?;
                info!("Our new config is:\n{:#?}", networkd_config);
                networkd_config
            };

            info!("Restarting systemd-networkd");
            NetworkdConfiguration::restart().await?;

            let mut interval = interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                // Wait a bit between each attempt at starting the main loop.
                //
                // If we don't have any kind of delay here we would be hammering the server with constant
                // requests if e.g. the Consul leader goes down and until a new leader is elected, since
                // creating a new session during that time fails with a 500 error.
                tokio::select! {
                    _ = top_level_token.cancelled() => {
                        trace!("Top level task cancelled, exiting");
                        break;
                    },
                    _ = interval.tick() => {},
                };

                if let Err(err) = inner_loop(
                    &consul_client,
                    &endpoint_address,
                    &networkd_config,
                    // This is the line that needs to change
                    &run_args,
                    top_level_token.child_token(),
                )
                .await
                {
                    error!("Inner loop exited with an error: {err:?}");
                }

                if top_level_token.is_cancelled() {
                    trace!("Top level task cancelled, exiting");
                    break;
                } else {
                    info!("Restarting wiresmith main loop");
                }
            }
        }
        Command::ApiServer(api_server_args) => {
            run_api_server(api_server_args).await?;
        }
    }

    Ok(())
}

async fn run_api_server(args: ApiServerArgs) -> Result<()> {
    let state = ApiState {
        kv_store: Arc::new(Mutex::new(HashMap::new())),
        datacenter_name: args.datacenter_name,
    };

    let app = Router::new()
        .route("/v1/agent/self", get(get_agent_self))
        .route("/v1/kv/:key", get(get_kv).put(put_kv))
        .with_state(state);

    let addr = args
        .listen_address
        .parse::<SocketAddr>()
        .context("Failed to parse listen address")?;

    info!("API server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service())
        .await
        .context("API server failed")?;

    Ok(())
}

async fn get_agent_self(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(json!({
        "Config": {
            "Datacenter": state.datacenter_name
        }
    }))
}

async fn get_kv(
    Path(key): Path<String>,
    State(state): State<ApiState>,
) -> Json<serde_json::Value> {
    let store = state.kv_store.lock().unwrap();
    match store.get(&key) {
        Some(value) => Json(json!([{
            "Key": key,
            "Value": value, // Values in Consul are base64 encoded, but we are storing raw strings for now
            "Flags": 0
        }])),
        None => Json(json!(null)),
    }
}

async fn put_kv(
    Path(key): Path<String>,
    State(state): State<ApiState>,
    Json(payload): Json<String>,
) -> Json<bool> {
    let mut store = state.kv_store.lock().unwrap();
    store.insert(key, payload); // Consul KV PUT body is raw, not JSON
    Json(true)
}

#[tracing::instrument(skip_all)]
async fn inner_loop(
    consul_client: &ConsulClient,
    endpoint_address: &str,
    networkd_config: &NetworkdConfiguration,
    run_args: &RunArgs,
    token: CancellationToken,
) -> Result<()> {
    // Create a Consul session to hold the config KV lock under.
    let consul_session = consul_client
        .create_session(networkd_config.public_key, token.clone())
        .await?;

    let own_wg_peer = WgPeer::new(
        networkd_config.public_key,
        &format!("{endpoint_address}:{}", run_args.wg_port),
        networkd_config.wg_address.addr(),
    );

    info!(
        "Submitting own WireGuard peer config to Consul:\n{:#?}",
        own_wg_peer
    );

    // Try to put our WireGuard peer config into Consul. On failures, which could have occurred due
    // to a session not yet having timed out, we retry 5 times before failing fully.
    let config_checker = 'cc: {
        let mut failures = 0;

        // We sleep for the TTL*2 between each attempt since after this amount of time any previously
        // held session should have expired. This corresponds to one period of the TTL and one
        // period of the default Consul session `LockDelay` which is also 15 seconds.
        let mut interval = interval(CONSUL_TTL * 2);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match consul_session.put_config(&own_wg_peer, token.clone()).await {
                Ok(config_checker) => break 'cc config_checker,
                Err(err) => {
                    failures += 1;
                    if failures >= 5 {
                        bail!("Failed to put node config {failures} times, exiting inner loop");
                    }
                    error!(
                        "Failed to put own node config into Consul ({failures} failed attempts): {err:?}"
                    );
                }
            };
        }
    };
    info!("Wrote own WireGuard peer config to Consul");

    // Enter main loop which periodically checks for updates to the list of WireGuard peers.
    loop {
        trace!("Checking Consul for peer updates");
        let peers = consul_client
            .get_peers()
            .await
            .context("Can't fetch existing peers from Consul")?;
        let mut networkd_config =
            NetworkdConfiguration::from_config(&run_args.networkd_dir, &run_args.wg_interface)
                .await
                .context("Couldn't load existing NetworkdConfiguration from disk")?;

        // Exclude own peer config.
        let peers_without_own_config = peers
            .iter()
            .filter(|&x| x.public_key != networkd_config.public_key)
            .cloned()
            .collect::<HashSet<WgPeer>>();

        // If there is a mismatch, write a new networkd configuration.
        let additional_peers = peers_without_own_config
            .difference(&networkd_config.peers)
            .collect::<Vec<_>>();
        let deleted_peers = networkd_config
            .peers
            .difference(&peers_without_own_config)
            .collect::<Vec<_>>();
        if !additional_peers.is_empty() {
            info!("Found {} new peer(s) in Consul", additional_peers.len());
            debug!("New peers: {:#?}", additional_peers);
        }
        if !deleted_peers.is_empty() {
            info!("Found {} deleted peer(s) in Consul", deleted_peers.len());
            debug!("Deleted peers: {:#?}", deleted_peers);
        }

        if !additional_peers.is_empty() || !deleted_peers.is_empty() {
            networkd_config.peers = peers_without_own_config;
            networkd_config
                .write_config(&run_args.networkd_dir, run_args.keepalive)
                .await
                .context("Couldn't write new NetworkdConfiguration")?;

            info!("Restarting systemd-networkd to apply new config");
            NetworkdConfiguration::restart()
                .await
                .context("Error restarting systemd-networkd")?;
        }

        // Wait until we've either been told to shut down or until we've slept for the update
        // period.
        //
        // TODO: Use long polling instead of periodic checks.
        tokio::select! {
            _ = token.cancelled() => {
                trace!("Main loop cancelled, exiting");
                break;
            },
            _ = sleep(run_args.update_period) => continue,
        };
    }

    // Cancel the config checker first so we don't get spurious errors if the session is destroyed
    // first.
    trace!("Cancelling config checker");
    config_checker
        .cancel()
        .await
        .context("Failed to join Consul config checker task")?;

    // Wait for the Consul session handler to destroy our session and exit. It was cancelled by the
    // same `CancellationToken` that cancelled us.
    trace!("Cancelling session handler");
    consul_session
        .cancel()
        .await
        .context("Failed to join Consul session handler task")?;

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body}; // Updated to include to_bytes
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for `oneshot` and `ready`

    #[tokio::test]
    async fn test_api_server_agent_self() {
        let test_datacenter = "test-dc1".to_string();
        let state = ApiState {
            kv_store: Arc::new(Mutex::new(HashMap::new())),
            datacenter_name: test_datacenter.clone(),
        };

        // Directly call the handler
        let response = get_agent_self(State(state)).await;

        assert_eq!(response.0, json!({"Config": {"Datacenter": test_datacenter}}));
    }

    #[tokio::test]
    async fn test_api_server_kv_put_get() {
        let state = ApiState {
            kv_store: Arc::new(Mutex::new(HashMap::new())),
            datacenter_name: "test-dc".to_string(),
        };

        let test_key = "my/test/key".to_string();
        let test_value = "my test value".to_string();

        // Test PUT
        let put_response = put_kv(
            Path(test_key.clone()),
            State(state.clone()),
            Json(test_value.clone()),
        )
        .await;
        assert_eq!(put_response.0, true);

        // Verify that the value was stored
        {
            let store = state.kv_store.lock().unwrap();
            assert_eq!(store.get(&test_key), Some(&test_value));
        }

        // Test GET
        let get_response = get_kv(Path(test_key.clone()), State(state.clone())).await;
        assert_eq!(
            get_response.0,
            json!([{
                "Key": test_key,
                "Value": test_value,
                "Flags": 0
            }])
        );

        // Test GET for a non-existent key
        let get_none_response = get_kv(Path("nonexistent/key".to_string()), State(state.clone())).await;
        assert_eq!(get_none_response.0, json!(null));
    }

    // Example test using a full Axum app (optional, as direct handler testing is often simpler)
    #[tokio::test]
    async fn test_api_server_agent_self_with_app() {
        let test_datacenter = "test-dc-app".to_string();
        let state = ApiState {
            kv_store: Arc::new(Mutex::new(HashMap::new())),
            datacenter_name: test_datacenter.clone(),
        };

        let app = Router::new()
            .route("/v1/agent/self", get(get_agent_self))
            .with_state(state);

        let request = Request::builder()
            .uri("/v1/agent/self")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap(); // Changed to axum::body::to_bytes
        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_json, json!({"Config": {"Datacenter": test_datacenter}}));
    }
}
