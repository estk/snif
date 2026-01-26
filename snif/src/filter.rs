use glob::Pattern;
use ipnetwork::IpNetwork;
use regex::Regex;
use snif_common::{ADDR_SIZE, Data, Kind};
use std::{net::IpAddr, ops::RangeInclusive};

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

/// Parsed port filter value (supports single ports and ranges)
#[derive(Clone, Debug)]
pub enum PortFilter {
    Either(RangeInclusive<u16>),
    Local(RangeInclusive<u16>),
    Peer(RangeInclusive<u16>),
}

impl PortFilter {
    /// Parse a port or port range (e.g., "443" or "80-443")
    fn parse_port_or_range(s: &str) -> Result<RangeInclusive<u16>, String> {
        let s = s.trim();
        if let Some((min, max)) = s.split_once('-') {
            let min = min
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("invalid port '{}': {}", min, e))?;
            let max = max
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("invalid port '{}': {}", max, e))?;
            if min > max {
                return Err(format!(
                    "min port ({}) cannot be greater than max ({})",
                    min, max
                ));
            }
            Ok(min..=max)
        } else {
            let port = s
                .parse::<u16>()
                .map_err(|e| format!("invalid port '{}': {}", s, e))?;
            Ok(port..=port)
        }
    }

    /// Parse comma-separated ports/ranges with optional prefix: "local:80,443,8000-9000" or "peer:443" or "80-443"
    pub fn parse_list(s: &str) -> Result<Vec<Self>, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("local:") {
            rest.split(',')
                .map(|p| Self::parse_port_or_range(p).map(PortFilter::Local))
                .collect()
        } else if let Some(rest) = s.strip_prefix("peer:") {
            rest.split(',')
                .map(|p| Self::parse_port_or_range(p).map(PortFilter::Peer))
                .collect()
        } else {
            s.split(',')
                .map(|p| Self::parse_port_or_range(p).map(PortFilter::Either))
                .collect()
        }
    }

    /// Check if this filter matches the given ports
    pub fn matches(&self, local_port: u16, peer_port: u16) -> bool {
        match self {
            PortFilter::Either(range) => range.contains(&local_port) || range.contains(&peer_port),
            PortFilter::Local(range) => range.contains(&local_port),
            PortFilter::Peer(range) => range.contains(&peer_port),
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
    /// Parse comma-separated addresses with optional prefix: "local:10.0.0.1,10.0.0.2" or "peer:192.168.*.*"
    pub fn parse_list(s: &str) -> Result<Vec<Self>, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("local:") {
            rest.split(',')
                .map(|a| AddrMatcher::parse(a.trim()).map(AddrFilter::Local))
                .collect()
        } else if let Some(rest) = s.strip_prefix("peer:") {
            rest.split(',')
                .map(|a| AddrMatcher::parse(a.trim()).map(AddrFilter::Peer))
                .collect()
        } else {
            s.split(',')
                .map(|a| AddrMatcher::parse(a.trim()).map(AddrFilter::Either))
                .collect()
        }
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
    pub size_bytes: Option<RangeInclusive<usize>>,
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
            size_bytes: None,
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
        if let Some(bytes_range) = &self.size_bytes {
            if !bytes_range.contains(&size) {
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
    fn test_port_filter_parse_single() {
        let filters = PortFilter::parse_list("443").unwrap();
        assert_eq!(filters.len(), 1);
        assert!(filters[0].matches(443, 0));

        let filters = PortFilter::parse_list("local:8080").unwrap();
        assert_eq!(filters.len(), 1);
        assert!(matches!(filters[0], PortFilter::Local(_)));
        assert!(filters[0].matches(8080, 0));

        let filters = PortFilter::parse_list("peer:80").unwrap();
        assert_eq!(filters.len(), 1);
        assert!(matches!(filters[0], PortFilter::Peer(_)));
        assert!(filters[0].matches(0, 80));
    }

    #[test]
    fn test_port_filter_parse_range() {
        // Single range
        let filters = PortFilter::parse_list("80-443").unwrap();
        assert_eq!(filters.len(), 1);
        assert!(filters[0].matches(80, 0));
        assert!(filters[0].matches(200, 0));
        assert!(filters[0].matches(443, 0));
        assert!(!filters[0].matches(444, 0));

        // Range with prefix
        let filters = PortFilter::parse_list("local:8000-9000").unwrap();
        assert_eq!(filters.len(), 1);
        assert!(matches!(filters[0], PortFilter::Local(_)));
        assert!(filters[0].matches(8500, 0));
        assert!(!filters[0].matches(0, 8500)); // peer port shouldn't match

        // Mixed ports and ranges
        let filters = PortFilter::parse_list("80,443,8000-9000").unwrap();
        assert_eq!(filters.len(), 3);
        assert!(filters[0].matches(80, 0));
        assert!(filters[1].matches(443, 0));
        assert!(filters[2].matches(8500, 0));
    }

    #[test]
    fn test_port_filter_parse_list() {
        // Prefix applies to all ports in the list
        let filters = PortFilter::parse_list("local:80,443,8080").unwrap();
        assert_eq!(filters.len(), 3);
        assert!(matches!(filters[0], PortFilter::Local(_)));
        assert!(matches!(filters[1], PortFilter::Local(_)));
        assert!(matches!(filters[2], PortFilter::Local(_)));

        // No prefix means Either
        let filters = PortFilter::parse_list("80,443").unwrap();
        assert_eq!(filters.len(), 2);
        assert!(matches!(filters[0], PortFilter::Either(_)));
        assert!(matches!(filters[1], PortFilter::Either(_)));
    }

    #[test]
    fn test_port_filter_matches() {
        assert!(PortFilter::Either(80..=80).matches(80, 0));
        assert!(PortFilter::Either(80..=80).matches(0, 80));
        assert!(!PortFilter::Either(80..=80).matches(8080, 443));

        assert!(PortFilter::Local(80..=80).matches(80, 443));
        assert!(!PortFilter::Local(80..=80).matches(443, 80));

        assert!(PortFilter::Peer(443..=443).matches(80, 443));
        assert!(!PortFilter::Peer(443..=443).matches(443, 80));

        // Range matches
        assert!(PortFilter::Either(80..=443).matches(200, 0));
        assert!(PortFilter::Either(80..=443).matches(0, 200));
        assert!(!PortFilter::Either(80..=443).matches(444, 500));
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
        let filters = AddrFilter::parse_list("10.0.0.1").unwrap();
        assert_eq!(filters.len(), 1);
        assert!(matches!(filters[0], AddrFilter::Either(_)));

        let filters = AddrFilter::parse_list("local:127.0.0.1").unwrap();
        assert_eq!(filters.len(), 1);
        assert!(matches!(filters[0], AddrFilter::Local(_)));

        let filters = AddrFilter::parse_list("peer:192.168.0.0/16").unwrap();
        assert_eq!(filters.len(), 1);
        assert!(matches!(filters[0], AddrFilter::Peer(_)));
    }

    #[test]
    fn test_addr_filter_parse_list() {
        // Prefix applies to all addresses in the list
        let filters = AddrFilter::parse_list("local:10.0.0.1,10.0.0.2,10.0.0.3").unwrap();
        assert_eq!(filters.len(), 3);
        assert!(matches!(filters[0], AddrFilter::Local(_)));
        assert!(matches!(filters[1], AddrFilter::Local(_)));
        assert!(matches!(filters[2], AddrFilter::Local(_)));

        // No prefix means Either
        let filters = AddrFilter::parse_list("10.0.0.1,192.168.1.1").unwrap();
        assert_eq!(filters.len(), 2);
        assert!(matches!(filters[0], AddrFilter::Either(_)));
        assert!(matches!(filters[1], AddrFilter::Either(_)));
    }
}
