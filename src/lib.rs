use std::{net::IpAddr, time::Duration};

use pnet::{datalink::NetworkInterface, ipnetwork::IpNetwork};

pub mod consul;
pub mod networkd;
pub mod wireguard;

pub const CONSUL_TTL: Duration = Duration::from_secs(15);

pub fn first_public_ipv6(interface: &NetworkInterface) -> Option<&IpNetwork> {
    interface.ips.iter().find(|network| {
        let ip = network.ip();
        ip.is_ipv6()
            && !ip.is_loopback()
            && !ip.is_multicast()
            && !is_link_local_v6(ip)
            && !is_unique_local_v6(ip)
    })
}

pub fn is_link_local_v6(ip: IpAddr) -> bool {
    if let IpAddr::V6(ipv6) = ip {
        let segments = ipv6.segments();
        segments[0] & 0xffc0 == 0xfe80
    } else {
        false
    }
}

pub fn is_unique_local_v6(ip: IpAddr) -> bool {
    if let IpAddr::V6(ipv6) = ip {
        let segments = ipv6.segments();
        segments[0] & 0xfe00 == 0xfc00
    } else {
        false
    }
}
