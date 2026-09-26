use std::net::Ipv4Addr;
use std::str::FromStr;

use tracing::{debug, info, warn};

use super::loader::EbpfLoader;
use crate::error::{NetworkAgentError, NetworkResult};

pub struct EbpfLeaseManager {
    loader: EbpfLoader,
}

impl EbpfLeaseManager {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { loader }
    }

    pub fn apply_lease_cidrs(
        &self,
        sandbox_id: &str,
        egress_cidrs: &[String],
    ) -> NetworkResult<usize> {
        let mut inserted = 0usize;

        debug!(
            sandbox_id = %sandbox_id,
            cidr_count = egress_cidrs.len(),
            "applying lease egress CIDRs to BPF allow map"
        );

        for cidr in egress_cidrs {
            let ips = expand_cidr(cidr).map_err(|_e| NetworkAgentError::InvalidCidr {
                cidr: cidr.to_string(),
            })?;

            for ip in ips {
                let ip_be = u32::from_be_bytes(ip.octets());
                match self.loader.insert_allow_entry(ip_be) {
                    Ok(()) => inserted += 1,
                    Err(e) => {
                        warn!(
                            sandbox_id = %sandbox_id,
                            cidr = %cidr,
                            ip = %ip,
                            error = %e,
                            "failed to insert lease CIDR into BPF allow map"
                        );
                    }
                }
            }
        }

        info!(
            sandbox_id = %sandbox_id,
            cidrs = ?egress_cidrs,
            ips_inserted = inserted,
            "lease egress CIDRs applied to BPF"
        );

        Ok(inserted)
    }

    pub fn remove_lease_cidrs(
        &self,
        sandbox_id: &str,
        egress_cidrs: &[String],
    ) -> NetworkResult<usize> {
        let mut removed = 0usize;

        debug!(
            sandbox_id = %sandbox_id,
            cidr_count = egress_cidrs.len(),
            "removing lease egress CIDRs from BPF allow map"
        );

        for cidr in egress_cidrs {
            let ips = match expand_cidr(cidr) {
                Ok(ips) => ips,
                Err(_) => continue,
            };

            for ip in ips {
                let ip_be = u32::from_be_bytes(ip.octets());
                match self.loader.remove_allow_entry(ip_be) {
                    Ok(()) => removed += 1,
                    Err(_) => {
                        debug!(
                            sandbox_id = %sandbox_id,
                            ip = %ip,
                            "allow entry already removed or not found"
                        );
                    }
                }
            }
        }

        info!(
            sandbox_id = %sandbox_id,
            cidrs = ?egress_cidrs,
            ips_removed = removed,
            "lease egress CIDRs removed from BPF"
        );

        Ok(removed)
    }

    pub fn replace_lease_cidrs(
        &self,
        sandbox_id: &str,
        old_cidrs: &[String],
        new_cidrs: &[String],
    ) -> NetworkResult<(usize, usize)> {
        let removed = self.remove_lease_cidrs(sandbox_id, old_cidrs)?;
        let inserted = self.apply_lease_cidrs(sandbox_id, new_cidrs)?;
        Ok((removed, inserted))
    }

    pub fn apply_dns_resolved_ips(
        &self,
        sandbox_id: &str,
        resolved_ips: &[Ipv4Addr],
    ) -> NetworkResult<usize> {
        let mut inserted = 0usize;

        for ip in resolved_ips {
            let ip_be = u32::from_be_bytes(ip.octets());
            match self.loader.insert_allow_entry(ip_be) {
                Ok(()) => inserted += 1,
                Err(e) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        ip = %ip,
                        error = %e,
                        "failed to insert DNS-resolved IP into BPF allow map"
                    );
                }
            }
        }

        debug!(
            sandbox_id = %sandbox_id,
            ips = ?resolved_ips,
            inserted = inserted,
            "DNS-resolved IPs added to BPF allow map"
        );

        Ok(inserted)
    }

    pub fn remove_dns_resolved_ips(
        &self,
        sandbox_id: &str,
        resolved_ips: &[Ipv4Addr],
    ) -> NetworkResult<usize> {
        let mut removed = 0usize;

        for ip in resolved_ips {
            let ip_be = u32::from_be_bytes(ip.octets());
            if self.loader.remove_allow_entry(ip_be).is_ok() {
                removed += 1;
            }
        }

        debug!(
            sandbox_id = %sandbox_id,
            ips = ?resolved_ips,
            removed = removed,
            "DNS-resolved IPs removed from BPF allow map"
        );

        Ok(removed)
    }
}

fn expand_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR format: {cidr}"))?;

    let addr =
        Ipv4Addr::from_str(addr_str).map_err(|e| format!("invalid IP in CIDR {cidr}: {e}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| format!("invalid prefix in CIDR {cidr}: {e}"))?;

    if prefix > 32 {
        return Err(format!("prefix too large: {prefix}"));
    }

    let host_bits = 32 - prefix;
    let count = 1u64 << host_bits as u64;

    if count > 256 {
        return Err(format!(
            "CIDR {cidr} expands to {count} IPs, refusing to expand"
        ));
    }

    let network = u32::from_be_bytes(addr.octets());
    let mut ips = Vec::with_capacity(count as usize);

    for i in 0..count {
        ips.push(Ipv4Addr::from_bits(network.wrapping_add(i as u32)));
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_single_ip() {
        let ips = expand_cidr("10.0.0.1/32").unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn expand_small_subnet() {
        let ips = expand_cidr("10.0.0.0/30").unwrap();
        assert_eq!(ips.len(), 4);
    }

    #[test]
    fn expand_rejects_large_subnet() {
        assert!(expand_cidr("10.0.0.0/8").is_err());
    }

    #[test]
    fn expand_invalid_input() {
        assert!(expand_cidr("not-a-cidr").is_err());
        assert!(expand_cidr("10.0.0.0/33").is_err());
        assert!(expand_cidr("").is_err());
    }
}
