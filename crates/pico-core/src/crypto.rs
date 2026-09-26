//! Shared cryptographic utilities for the PicoCompute host-agent and guest-agent.
//!
//! Provides BLAKE3 keyed MAC, secure random generation, constant-time comparison,
//! and the handshake shared-secret derivation.

use heapless::Vec as HVec;
use rand::Rng;
use sha2::{Digest, Sha256};

/// BLAKE3 keyed MAC producing a 32-byte authentication tag.
pub fn blake3_mac(key: &[u8], data: &[u8]) -> HVec<u8, 32> {
    let derived_key: [u8; 32] = if key.len() == 32 {
        key.try_into().unwrap()
    } else {
        blake3::hash(key).into()
    };
    let hash = blake3::keyed_hash(&derived_key, data);
    HVec::from_slice(hash.as_bytes()).expect("blake3 output is exactly 32 bytes")
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub fn generate_random_bytes<const N: usize>() -> HVec<u8, N> {
    let mut buf: HVec<u8, N> = HVec::new();
    buf.resize(N, 0).expect("N <= capacity");
    rand::rng().fill_bytes(&mut buf);
    buf
}

pub fn generate_nonce() -> HVec<u8, 32> {
    generate_random_bytes::<32>()
}

pub fn generate_session_id() -> HVec<u8, 16> {
    generate_random_bytes::<16>()
}

/// Derives the handshake shared secret from a sandbox identity.
///
/// NOTE: This derivation is deterministic per sandbox_id and has no per-boot
/// entropy.  Security relies on network isolation (the guest-agent TCP port
/// is only reachable from within the VM).  A future revision should include
/// a per-boot random component injected via kernel command-line so that the
/// secret is only known to the host and the correct guest image.
pub fn derive_handshake_shared_secret(sandbox_id: &str) -> HVec<u8, 32> {
    let mut hasher = Sha256::new();
    hasher.update(b"pico.handshake.shared-secret.v1");
    hasher.update(sandbox_id.as_bytes());
    let hash = hasher.finalize();
    HVec::from_slice(&hash).expect("sha256 output is exactly 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_mac_is_deterministic() {
        let key = b"32-byte-test-key-here-123456!";
        let data = b"test data";
        let h1 = blake3_mac(key, data);
        let h2 = blake3_mac(key, data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn blake3_mac_differs_with_key() {
        let data = b"test data";
        let h1 = blake3_mac(b"key-1-1234567890abcdef12345678", data);
        let h2 = blake3_mac(b"key-2-1234567890abcdef12345678", data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake3_mac_handles_short_key() {
        let short_key = b"short";
        let data = b"test";
        let mac = blake3_mac(short_key, data);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn generate_nonce_is_32_bytes() {
        assert_eq!(generate_nonce().len(), 32);
    }

    #[test]
    fn generate_session_id_is_16_bytes() {
        assert_eq!(generate_session_id().len(), 16);
    }

    #[test]
    fn derive_shared_secret_is_stable() {
        let s1 = derive_handshake_shared_secret("sbx_test");
        let s2 = derive_handshake_shared_secret("sbx_test");
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn derive_shared_secret_varies_with_sandbox_id() {
        let s1 = derive_handshake_shared_secret("sbx_alpha");
        let s2 = derive_handshake_shared_secret("sbx_beta");
        assert_ne!(s1, s2);
    }
}
