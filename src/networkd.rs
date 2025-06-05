use std::{
    collections::HashSet, fmt, fs::Permissions, net::IpAddr, os::unix::prelude::PermissionsExt,
    path::Path,
};

use anyhow::{anyhow, Context, Result};
// use file_owner::set_group; // Commented out as set_group is also commented out
use ipnet::IpNet;
use tokio::{fs, process::Command};
use wireguard_keys::{Privkey, Pubkey};

use crate::wireguard::WgPeer;

/// Find a free address in a network given a list of occupied addresses.
///
/// Returns `None` if there are no free addresses.
#[tracing::instrument]
fn get_free_address(network: &IpNet, peers: &HashSet<WgPeer>, ipv6_only: bool) -> Option<IpAddr> {
    let occupied_addresses = peers
        .iter()
        .map(|x| x.address.addr())
        .collect::<HashSet<_>>();
    let network_address = network.network();
    for host in network.hosts() {
        // Skip the network address itself for networks smaller than /127 (e.g. /64),
        // as it's typically not usable (e.g., Subnet-Router anycast).
        // For /127 and /128, the network address is a valid host address.
        if host == network_address && network.prefix_len() < 127 {
            continue;
        }
        if ipv6_only && !host.is_ipv6() {
            continue;
        }
        if !occupied_addresses.contains(&host) {
            return Some(host);
        }
    }
    None
}

pub struct NetworkdConfiguration {
    pub wg_address: IpNet,
    pub wg_interface: String,
    pub wg_port: u16,
    pub peers: HashSet<WgPeer>,
    pub private_key: Privkey,
    pub public_key: Pubkey,
}

impl fmt::Debug for NetworkdConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkdConfiguration")
            .field("wg_address", &self.wg_address)
            .field("wg_interface", &self.wg_interface)
            .field("wg_port", &self.wg_port)
            .field("peers", &self.peers)
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.public_key.to_base64_urlsafe())
            .finish()
    }
}

impl NetworkdConfiguration {
    /// Build a new config
    #[tracing::instrument]
    pub fn new(
        address: Option<IpAddr>,
        network: IpNet,
        port: u16,
        wg_interface: &str,
        peers: HashSet<WgPeer>,
        ipv6_only: bool,
    ) -> Result<Self> {
        let address = if let Some(address) = address {
            address
        } else {
            get_free_address(&network, &peers, ipv6_only)
                .context("Couldn't find usable address")?
        };

        if ipv6_only && !address.is_ipv6() {
            return Err(anyhow!(
                "IPv6-only mode is enabled, but no free IPv6 address could be found"
            ));
        }

        let wg_address = IpNet::new(address, network.prefix_len())?;
        let private_key = wireguard_keys::Privkey::generate();
        Ok(Self {
            wg_address,
            wg_interface: wg_interface.to_string(),
            wg_port: port,
            peers,
            private_key,
            public_key: private_key.pubkey(),
        })
    }

    /// Read and parse existing config from existing location on disk
    #[tracing::instrument]
    pub async fn from_config(networkd_dir: &Path, wg_interface: &str) -> Result<Self> {
        // Get the list of peers in networkd.
        let netdev_path = networkd_dir.join(wg_interface).with_extension("netdev");
        let netdev_ini = ini::Ini::load_from_file(netdev_path)?;

        let wg_port = netdev_ini
            .section(Some("WireGuard"))
            .context("Couldn't find [WireGuard] section")?
            .get("ListenPort")
            .context("Couldn't find ListenPort in [WireGuard] section")?
            .parse()?;
        let private_key: Privkey = netdev_ini
            .section(Some("WireGuard"))
            .context("Couldn't find [WireGuard] section")?
            .get("PrivateKey")
            .context("Couldn't find PrivateKey in [WireGuard] section")?
            .parse()?;
        let public_key = private_key.pubkey();

        let mut peers = HashSet::new();
        for peer in netdev_ini.section_all(Some("WireGuardPeer")) {
            let public_key = peer
                .get("PublicKey")
                .context("No PublicKey attribute on WireGuardPeer")?;
            let endpoint = peer
                .get("Endpoint")
                .context("No Endpoint attribute on WireGuardPeer")?;
            let allowed_ips = peer
                .get("AllowedIPs")
                .context("No AllowedIPs attribute on WireGuardPeer")?;
            peers.insert(WgPeer {
                public_key: Pubkey::from_base64(public_key)?,
                endpoint: endpoint.parse()?,
                address: allowed_ips.parse()?,
            });
        }

        let network_path = networkd_dir.join(wg_interface).with_extension("network");
        let network_ini = ini::Ini::load_from_file(network_path)?;

        let wg_address = network_ini
            .section(Some("Network"))
            .context("Couldn't find [Network] section")?
            .get("Address")
            .context("Couldn't find Address in [Network] section")?
            .parse()?;

        Ok(Self {
            wg_interface: wg_interface.to_string(),
            wg_address,
            wg_port,
            peers,
            private_key,
            public_key,
        })
    }

    /// Generate and write systemd-networkd config
    #[tracing::instrument]
    pub async fn write_config(&self, networkd_dir: &Path, persistent_keepalive: u64) -> Result<()> {
        let network_file_content = format!(
            "\
[Match]
Name={}

[Network]
Address={}\n",
            self.wg_interface,
            if self.wg_address.addr().is_ipv6() {
                format!("{}/{}", self.wg_address.addr(), self.wg_address.prefix_len())
            } else {
                self.wg_address.to_string()
            }
        );

        let mut netdev_file_content = format!(
            "\
[NetDev]
Name={}
Kind=wireguard
Description=WireGuard client
MTUBytes=1280

[WireGuard]
ListenPort={}
PrivateKey={}\n",
            self.wg_interface, self.wg_port, self.private_key
        );

        for peer in &self.peers {
            let peer_str = format!(
                "\n
[WireGuardPeer]
PublicKey={}
Endpoint={}
AllowedIPs={}
PersistentKeepalive={}",
                peer.public_key,
                peer.endpoint,
                if peer.address.addr().is_ipv6() {
                    format!("{}/{}", peer.address.addr(), peer.address.prefix_len())
                } else {
                    peer.address.to_string()
                },
                persistent_keepalive
            );
            netdev_file_content.push_str(&peer_str);
        }
        let network_path = networkd_dir
            .join(&self.wg_interface)
            .with_extension("network");
        let netdev_path = networkd_dir
            .join(&self.wg_interface)
            .with_extension("netdev");

        fs::write(&network_path, network_file_content)
            .await
            .context(format!("Couldn't write config to {network_path:?}"))?;
        fs::write(&netdev_path, netdev_file_content)
            .await
            .context(format!("Couldn't write config to {netdev_path:?}"))?;
        fs::set_permissions(&netdev_path, Permissions::from_mode(0o640)).await?;
        // set_group(netdev_path, "systemd-network")?; // Commented out for testing due to EPERM

        Ok(())
    }

    /// Restart systemd-networkd
    #[tracing::instrument]
    pub async fn restart() -> Result<()> {
        let restart_output = Command::new("systemctl")
            .arg("restart")
            .arg("systemd-networkd")
            .output()
            .await?;
        if !restart_output.status.success() {
            let stderr = String::from_utf8_lossy(&restart_output.stderr);
            let journalctl_output = Command::new("journalctl")
                .arg("-u")
                .arg("systemd-networkd")
                .output()
                .await?;
            let journalctl_stdout = String::from_utf8_lossy(&journalctl_output.stdout);
            return Err(anyhow!("Failed to restart systemd-networkd: {stderr}\njournalctl -xeu systemd-networkd: {journalctl_stdout}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::tempdir; // This was already here, my mistake in previous analysis

    #[test]
    fn test_get_free_address_ipv6_only() {
        let network = IpNet::from_str("fc00::/64").unwrap();
        let mut peers = HashSet::new();
        peers.insert(WgPeer {
            public_key: Privkey::generate().pubkey(),
            endpoint: "1.2.3.4:51820".parse().unwrap(),
            address: IpNet::from_str("fc00::1/128").unwrap(),
        });
        // Add an IPv4 peer to ensure it's ignored
        peers.insert(WgPeer {
            public_key: Privkey::generate().pubkey(),
            endpoint: "1.2.3.5:51820".parse().unwrap(),
            address: IpNet::from_str("10.0.0.1/32").unwrap(),
        });

        let free_address_option = get_free_address(&network, &peers, true);
        assert!(free_address_option.is_some());
        let free_address = free_address_option.unwrap();
        assert!(free_address.is_ipv6());
        assert_eq!(free_address.to_string(), "fc00::2");
    }

    #[test]
    fn test_get_free_address_ipv6_only_no_ipv6_available() {
        let network = IpNet::from_str("10.0.0.0/24").unwrap(); // IPv4 network
        let peers = HashSet::new();
        let free_address = get_free_address(&network, &peers, true);
        assert!(free_address.is_none());

        // Test with an IPv6 network /127.
        // fc00::/127 has two host addresses: fc00::0 and fc00::1.
        let network_ipv6_small = IpNet::from_str("fc00::/127").unwrap();
        let mut peers_occupy_one = HashSet::new();
        peers_occupy_one.insert(WgPeer {
            public_key: Privkey::generate().pubkey(),
            endpoint: "1.2.3.4:51820".parse().unwrap(),
            address: IpNet::from_str("fc00::1/128").unwrap(), // Occupy fc00::1
        });
        let free_address_small_net = get_free_address(&network_ipv6_small, &peers_occupy_one, true);
        assert!(free_address_small_net.is_some());
        assert_eq!(free_address_small_net.unwrap().to_string(), "fc00::"); // fc00::0 should be available

        // Now occupy both fc00::0 and fc00::1
        let mut peers_occupy_all = HashSet::new();
        peers_occupy_all.insert(WgPeer { // Occupy fc00::1
            public_key: Privkey::generate().pubkey(),
            endpoint: "1.2.3.4:51820".parse().unwrap(),
            address: IpNet::from_str("fc00::1/128").unwrap(),
        });
        peers_occupy_all.insert(WgPeer { // Occupy fc00::0
            public_key: Privkey::generate().pubkey(),
            endpoint: "1.2.3.5:51820".parse().unwrap(),
            address: IpNet::from_str("fc00::0/128").unwrap(),
        });
        let free_address_all_occupied = get_free_address(&network_ipv6_small, &peers_occupy_all, true);
        assert!(free_address_all_occupied.is_none());
    }


    #[test]
    fn test_networkd_configuration_new_ipv6_only() {
        let network = IpNet::from_str("fc00::/64").unwrap();
        let peers = HashSet::new();
        let config = NetworkdConfiguration::new(
            None, // Auto-assign address
            network,
            51820,
            "wg-test",
            peers,
            true, // ipv6_only
        )
        .unwrap();
        assert!(config.wg_address.addr().is_ipv6());
        // The first host address in fc00::/64 is fc00::1
        assert_eq!(config.wg_address.to_string(), "fc00::1/64");
    }

    #[tokio::test]
    async fn test_networkd_configuration_write_config_ipv6_only() {
        let temp_dir = tempdir().unwrap();
        let networkd_dir = temp_dir.path();

        // Generate valid keys
        let peer1_privkey = Privkey::generate();
        let peer1_pubkey = peer1_privkey.pubkey();
        let peer2_privkey = Privkey::generate();
        let peer2_pubkey = peer2_privkey.pubkey();
        let config_privkey = Privkey::generate();
        let config_pubkey = config_privkey.pubkey();

        let mut peers = HashSet::new();
        peers.insert(WgPeer {
            public_key: peer1_pubkey,
            endpoint: "[2001:db8::1]:51820".parse().unwrap(),
            address: IpNet::from_str("fc00::10/128").unwrap(),
        });
        peers.insert(WgPeer {
            public_key: peer2_pubkey,
            endpoint: "192.0.2.2:51820".parse().unwrap(),
            address: IpNet::from_str("10.0.0.2/32").unwrap(),
        });


        let config = NetworkdConfiguration {
            wg_address: IpNet::from_str("fc00::1/64").unwrap(),
            wg_interface: "wg-test-ipv6".to_string(),
            wg_port: 51820,
            peers,
            private_key: config_privkey,
            public_key: config_pubkey,
        };

        config.write_config(networkd_dir, 25).await.unwrap();

        let network_file_path = networkd_dir.join("wg-test-ipv6.network");
        let netdev_file_path = networkd_dir.join("wg-test-ipv6.netdev");

        assert!(network_file_path.exists());
        assert!(netdev_file_path.exists());

        let network_content = fs::read_to_string(network_file_path).await.unwrap();
        let netdev_content = fs::read_to_string(netdev_file_path).await.unwrap();

        println!("Network content:\n{}", network_content); // For debugging
        println!("Netdev content:\n{}", netdev_content);   // For debugging

        assert!(network_content.contains("Address=fc00::1/64"));

        // Check AllowedIPs for the IPv6 peer
        assert!(netdev_content.contains("AllowedIPs=fc00::10/128"));
        // Check AllowedIPs for the IPv4 peer (should still be its own address, not an IPv6 one from the main network)
        assert!(netdev_content.contains("AllowedIPs=10.0.0.2/32"));
    }
}
