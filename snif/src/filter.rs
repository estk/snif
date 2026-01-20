use glob::Pattern;
use ipnetwork::IpNetwork;
use regex::Regex;
use snif_common::{ADDR_SIZE, Data, Kind};
use std::net::IpAddr;

/// Traffic direction filter
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Direction {
    /// Only show incoming traffic (reads/requests to server)
    Incoming,
    /// Only show outgoing traffic (writes/responses from server)
    Outgoing,
    /// Show both incoming and outgoing traffic
    #[default]
    Both,
}

/// Parsed port filter value
#[derive(Clone, Debug)]
pub enum PortFilter {
    Either(u16),
    Local(u16),
    Peer(u16),
}

impl PortFilter {
    /// Parse a single port filter: "443", "local:443", or "peer:443"
    pub fn parse_single(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("local:") {
            let port = rest
                .parse::<u16>()
                .map_err(|e| format!("invalid port number '{}': {}", rest, e))?;
            Ok(PortFilter::Local(port))
        } else if let Some(rest) = s.strip_prefix("peer:") {
            let port = rest
                .parse::<u16>()
                .map_err(|e| format!("invalid port number '{}': {}", rest, e))?;
            Ok(PortFilter::Peer(port))
        } else {
            let port = s
                .parse::<u16>()
                .map_err(|e| format!("invalid port number '{}': {}", s, e))?;
            Ok(PortFilter::Either(port))
        }
    }

    /// Parse comma-separated port filters: "local:80,peer:443"
    pub fn parse_list(s: &str) -> Result<Vec<Self>, String> {
        s.split(',').map(Self::parse_single).collect()
    }

    /// Check if this filter matches the given ports
    pub fn matches(&self, local_port: u16, peer_port: u16) -> bool {
        match self {
            PortFilter::Either(port) => local_port == *port || peer_port == *port,
            PortFilter::Local(port) => local_port == *port,
            PortFilter::Peer(port) => peer_port == *port,
        }
    }
}

/// Address matching strategy
#[derive(Clone, Debug)]
pub enum AddrMatcher {
    Exact(IpAddr),
    Cidr(IpNetwork),
    Glob(Pattern),
}

impl AddrMatcher {
    /// Parse a string as IP, CIDR, or glob pattern
    pub fn parse(s: &str) -> Result<Self, String> {
        // Try to parse as exact IP
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(AddrMatcher::Exact(ip));
        }

        // Try to parse as CIDR
        if let Ok(network) = s.parse::<IpNetwork>() {
            return Ok(AddrMatcher::Cidr(network));
        }

        // Check if it contains glob characters
        if s.contains('*') || s.contains('?') || s.contains('[') {
            let pattern =
                Pattern::new(s).map_err(|e| format!("invalid glob pattern '{}': {}", s, e))?;
            return Ok(AddrMatcher::Glob(pattern));
        }

        Err(format!(
            "'{}' is not a valid IP address, CIDR, or glob pattern",
            s
        ))
    }

    /// Check if an IP address matches this filter
    pub fn matches(&self, addr: IpAddr) -> bool {
        match self {
            AddrMatcher::Exact(expected) => addr == *expected,
            AddrMatcher::Cidr(network) => network.contains(addr),
            AddrMatcher::Glob(pattern) => pattern.matches(&addr.to_string()),
        }
    }
}

/// Parsed address filter value
#[derive(Clone, Debug)]
pub enum AddrFilter {
    Either(AddrMatcher),
    Local(AddrMatcher),
    Peer(AddrMatcher),
}

impl AddrFilter {
    /// Parse a single address filter: "10.0.0.1", "local:10.0.0.0/24", "peer:192.168.*.*"
    pub fn parse_single(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("local:") {
            let matcher = AddrMatcher::parse(rest)?;
            Ok(AddrFilter::Local(matcher))
        } else if let Some(rest) = s.strip_prefix("peer:") {
            let matcher = AddrMatcher::parse(rest)?;
            Ok(AddrFilter::Peer(matcher))
        } else {
            let matcher = AddrMatcher::parse(s)?;
            Ok(AddrFilter::Either(matcher))
        }
    }

    /// Parse comma-separated address filters: "local:127.0.0.1,peer:10.0.0.0/24"
    pub fn parse_list(s: &str) -> Result<Vec<Self>, String> {
        s.split(',').map(Self::parse_single).collect()
    }

    /// Check if this filter matches the given addresses
    pub fn matches(&self, local_addr: Option<IpAddr>, peer_addr: Option<IpAddr>) -> bool {
        match self {
            AddrFilter::Either(matcher) => {
                local_addr.map(|a| matcher.matches(a)).unwrap_or(false)
                    || peer_addr.map(|a| matcher.matches(a)).unwrap_or(false)
            }
            AddrFilter::Local(matcher) => local_addr.map(|a| matcher.matches(a)).unwrap_or(false),
            AddrFilter::Peer(matcher) => peer_addr.map(|a| matcher.matches(a)).unwrap_or(false),
        }
    }
}

/// All filter options combined
pub struct Filters {
    pub pid: Option<u32>,
    pub process: Option<Pattern>,
    pub ports: Vec<PortFilter>,
    pub addrs: Vec<AddrFilter>,
    pub min_size: Option<usize>,
    pub max_size: Option<usize>,
    pub contains_regex: Option<Regex>,
    pub header_match: Option<Regex>,
    pub header_name: Option<String>,
    pub direction: Direction,
}

impl Default for Filters {
    fn default() -> Self {
        Self {
            pid: None,
            process: None,
            ports: Vec::new(),
            addrs: Vec::new(),
            min_size: None,
            max_size: None,
            contains_regex: None,
            header_match: None,
            header_name: None,
            direction: Direction::Both,
        }
    }
}

impl Filters {
    /// Extract IP address from Data based on family
    fn extract_addr(family: u16, addr: &[u8; ADDR_SIZE]) -> Option<IpAddr> {
        const AF_INET: u16 = 2;
        const AF_INET6: u16 = 10;

        // Check if address is all zeros
        if addr.iter().all(|&b| b == 0) {
            return None;
        }

        if family == AF_INET {
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                addr[0], addr[1], addr[2], addr[3],
            )))
        } else if family == AF_INET6 {
            Some(IpAddr::V6(std::net::Ipv6Addr::from(*addr)))
        } else {
            None
        }
    }

    /// Extract payload from Data as a string slice
    fn extract_payload(data: &Data) -> &[u8] {
        let safe_len = if data.len <= 0 {
            0
        } else if data.len as usize > snif_common::MAX_BUF_SIZE {
            snif_common::MAX_BUF_SIZE
        } else {
            data.len as usize
        };
        &data.buf[..safe_len]
    }

    /// Check if a Data event passes all filters
    pub fn matches(&self, data: &Data) -> bool {
        // PID filter (done in kernel already, but we can double-check)
        if let Some(pid) = self.pid {
            if data.tgid != pid {
                return false;
            }
        }

        // Process name filter
        if let Some(ref pattern) = self.process {
            let comm = String::from_utf8_lossy(&data.comm);
            let comm = comm.trim_end_matches('\0');
            if !pattern.matches(comm) {
                return false;
            }
        }

        // Port filters - if any ports specified, at least one must match
        if !self.ports.is_empty() {
            // Skip unknown ports (0) check - they always pass through
            if data.local_port != 0 || data.peer_port != 0 {
                let any_match = self
                    .ports
                    .iter()
                    .any(|pf| pf.matches(data.local_port, data.peer_port));
                if !any_match {
                    return false;
                }
            }
        }

        // Address filters - if any addresses specified, at least one must match
        if !self.addrs.is_empty() {
            let local_addr = Self::extract_addr(data.family, &data.local_addr);
            let peer_addr = Self::extract_addr(data.family, &data.peer_addr);

            // If both addresses are unknown, let it pass (SSL traffic without fd)
            if local_addr.is_none() && peer_addr.is_none() {
                // Continue - unknown addresses pass through
            } else {
                let any_match = self
                    .addrs
                    .iter()
                    .any(|af| af.matches(local_addr, peer_addr));
                if !any_match {
                    return false;
                }
            }
        }

        // Size filters
        let size = data.len as usize;
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }

        // Content regex filter
        if let Some(ref regex) = self.contains_regex {
            let payload = Self::extract_payload(data);
            let payload_str = String::from_utf8_lossy(payload);
            if !regex.is_match(&payload_str) {
                return false;
            }
        }

        // Header filters (simple line-based parsing for HTTP/1.x headers)
        if self.header_match.is_some() || self.header_name.is_some() {
            let payload = Self::extract_payload(data);
            let payload_str = String::from_utf8_lossy(payload);

            // Find the header section (before empty line)
            let header_section = payload_str
                .split("\r\n\r\n")
                .next()
                .or_else(|| payload_str.split("\n\n").next())
                .unwrap_or(&payload_str);

            if let Some(ref regex) = self.header_match {
                if !regex.is_match(header_section) {
                    return false;
                }
            }

            if let Some(ref name) = self.header_name {
                let name_lower = name.to_lowercase();
                let has_header = header_section.lines().any(|line| {
                    if let Some(colon_pos) = line.find(':') {
                        let header_name = line[..colon_pos].trim().to_lowercase();
                        header_name == name_lower
                    } else {
                        false
                    }
                });
                if !has_header {
                    return false;
                }
            }
        }

        // Direction filter
        match self.direction {
            Direction::Incoming => {
                if !matches!(data.kind, Kind::SslRead | Kind::SocketRead) {
                    return false;
                }
            }
            Direction::Outgoing => {
                if !matches!(data.kind, Kind::SslWrite | Kind::SocketWrite) {
                    return false;
                }
            }
            Direction::Both => {}
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_filter_parse() {
        assert!(matches!(
            PortFilter::parse_single("443").unwrap(),
            PortFilter::Either(443)
        ));
        assert!(matches!(
            PortFilter::parse_single("local:8080").unwrap(),
            PortFilter::Local(8080)
        ));
        assert!(matches!(
            PortFilter::parse_single("peer:80").unwrap(),
            PortFilter::Peer(80)
        ));
    }

    #[test]
    fn test_port_filter_parse_list() {
        let filters = PortFilter::parse_list("local:80,peer:443").unwrap();
        assert_eq!(filters.len(), 2);
    }

    #[test]
    fn test_port_filter_matches() {
        assert!(PortFilter::Either(80).matches(80, 0));
        assert!(PortFilter::Either(80).matches(0, 80));
        assert!(!PortFilter::Either(80).matches(8080, 443));

        assert!(PortFilter::Local(80).matches(80, 443));
        assert!(!PortFilter::Local(80).matches(443, 80));

        assert!(PortFilter::Peer(443).matches(80, 443));
        assert!(!PortFilter::Peer(443).matches(443, 80));
    }

    #[test]
    fn test_addr_matcher_exact() {
        let matcher = AddrMatcher::parse("10.0.0.1").unwrap();
        assert!(matcher.matches("10.0.0.1".parse().unwrap()));
        assert!(!matcher.matches("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_addr_matcher_cidr() {
        let matcher = AddrMatcher::parse("10.0.0.0/24").unwrap();
        assert!(matcher.matches("10.0.0.1".parse().unwrap()));
        assert!(matcher.matches("10.0.0.254".parse().unwrap()));
        assert!(!matcher.matches("10.0.1.1".parse().unwrap()));
    }

    #[test]
    fn test_addr_matcher_glob() {
        let matcher = AddrMatcher::parse("10.0.0.*").unwrap();
        assert!(matcher.matches("10.0.0.1".parse().unwrap()));
        assert!(matcher.matches("10.0.0.99".parse().unwrap()));
        assert!(!matcher.matches("10.0.1.1".parse().unwrap()));
    }

    #[test]
    fn test_addr_filter_parse() {
        assert!(matches!(
            AddrFilter::parse_single("10.0.0.1").unwrap(),
            AddrFilter::Either(_)
        ));
        assert!(matches!(
            AddrFilter::parse_single("local:127.0.0.1").unwrap(),
            AddrFilter::Local(_)
        ));
        assert!(matches!(
            AddrFilter::parse_single("peer:192.168.0.0/16").unwrap(),
            AddrFilter::Peer(_)
        ));
    }
}
