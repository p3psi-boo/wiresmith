use std::{net::IpAddr, path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};
use ipnet::IpNet;
use pnet::datalink::{self, NetworkInterface};
use reqwest::Url;

#[derive(Copy, Clone, ValueEnum, Debug, PartialEq)]
pub enum NetworkBackend {
    Networkd,
    // Wgquick
}

#[derive(Parser)]
#[command(name = "wiresmith", author, about, version)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug, PartialEq)] // Added PartialEq for test assertions
pub enum Command {
    Run(RunArgs),
    ApiServer(ApiServerArgs),
}

#[derive(Parser, Debug, PartialEq)] // Added PartialEq for test assertions
pub struct RunArgs {
    /// Consul backend socket address
    #[arg(long, default_value = "http://127.0.0.1:8500")]
    pub consul_address: Url,

    /// Consul secret token
    #[arg(long)]
    pub consul_token: Option<String>,

    /// Consul KV prefix
    #[arg(long, default_value = "wiresmith")]
    pub consul_prefix: String,

    /// Update period - how often to check for peer updates
    #[arg(short, long, default_value = "10s", value_parser = humantime::parse_duration)]
    pub update_period: Duration,

    /// WireGuard interface name
    #[arg(short = 'i', long, default_value = "wg0")]
    pub wg_interface: String,

    /// WireGuard UDP listen port
    #[arg(short = 'p', long, default_value = "51820")]
    pub wg_port: u16,

    /// Set persistent keepalive option for wireguard
    ///
    /// Set to 0 in order to disable.
    #[arg(short = 'k', long, default_value = "25s", value_parser = keep_alive)]
    pub keepalive: u64,

    /// Public endpoint interface name
    ///
    /// You need to provide either this or --endpoint-address.
    #[arg(long,
        required_unless_present = "endpoint_address",
        conflicts_with = "endpoint_address",
        value_parser = network_interface
    )]
    pub endpoint_interface: Option<NetworkInterface>,

    /// Public endpoint address
    ///
    /// Can be a hostname or IP address.
    /// You need to provide either this or --endpoint-interface.
    #[arg(
        long,
        required_unless_present = "endpoint_interface",
        conflicts_with = "endpoint_interface"
    )]
    pub endpoint_address: Option<String>,

    /// Network configuration backend
    #[arg(long, default_value = "networkd")]
    pub network_backend: NetworkBackend,

    /// Directory in which to place the generated networkd configuration
    #[arg(long, default_value = "/etc/systemd/network/")]
    pub networkd_dir: PathBuf,

    /// Address to allocate
    ///
    /// If not provided, will allocate available address from the subnet.
    /// For instance 10.0.0.4 or fc00::4
    #[arg(short, long)]
    pub address: Option<IpAddr>,

    /// Network to use
    ///
    /// Must be the same for all clients.
    /// For instance 10.0.0.0/24 or fc00::/64
    #[arg(short, long)]
    pub network: IpNet,

    /// Be verbose
    ///
    /// Provide twice for very verbose.
    #[arg(short, long, action = clap::ArgAction::Count, value_parser = clap::value_parser!(u8).range(0..=2))]
    pub verbose: u8,

    /// Use IPv6 only
    #[arg(long, default_value = "false")]
    pub ipv6_only: bool,
}

#[derive(Parser, Debug, PartialEq)] // Added PartialEq for test assertions
pub struct ApiServerArgs {
    /// Address to listen on for the API server
    #[arg(long, default_value = "127.0.0.1:8500")]
    pub listen_address: String,

    /// Name of the datacenter
    #[arg(long, default_value = "dc1")]
    pub datacenter_name: String,
}

fn network_interface(s: &str) -> Result<NetworkInterface, String> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty() && e.name == s);
    match interface {
        Some(i) => Ok(i.clone()),
        None => Err(format!("No usable interface found for '{}'", s)),
    }
}

fn keep_alive(s: &str) -> Result<u64, humantime::DurationError> {
    let duration = humantime::parse_duration(s)?;
    Ok(duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_api_server_subcommand() {
        let args = CliArgs::parse_from(["wiresmith", "api-server"]);
        match args.command {
            Command::ApiServer(api_args) => {
                assert_eq!(api_args.listen_address, "127.0.0.1:8500");
                assert_eq!(api_args.datacenter_name, "dc1");
            }
            _ => panic!("Expected ApiServer subcommand"),
        }

        let args_custom = CliArgs::parse_from([
            "wiresmith",
            "api-server",
            "--listen-address",
            "127.0.0.1:9000",
            "--datacenter-name",
            "dc2",
        ]);
        match args_custom.command {
            Command::ApiServer(api_args) => {
                assert_eq!(api_args.listen_address, "127.0.0.1:9000");
                assert_eq!(api_args.datacenter_name, "dc2");
            }
            _ => panic!("Expected ApiServer subcommand"),
        }
    }

    #[test]
    fn test_parse_ipv6_only_flag() {
        // We need to provide the required arguments for the Run subcommand
        let required_run_args = [
            "run",
            "--network",
            "10.0.0.0/24",
            "--endpoint-address",
            "1.2.3.4",
        ];

        // Test without the flag (should be false)
        let args_default = CliArgs::parse_from(["wiresmith"].iter().chain(&required_run_args));
        match args_default.command {
            Command::Run(run_args) => {
                assert!(!run_args.ipv6_only);
            }
            _ => panic!("Expected Run subcommand"),
        }

        // Test with the flag (should be true)
        let args_ipv6_only = CliArgs::parse_from(
            ["wiresmith"]
                .iter()
                .chain(&required_run_args)
                .chain(&["--ipv6-only"]),
        );
        match args_ipv6_only.command {
            Command::Run(run_args) => {
                assert!(run_args.ipv6_only);
            }
            _ => panic!("Expected Run subcommand"),
        }
    }
}
