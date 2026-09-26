//! Fuzz target for handshake parsing and negotiation.
//!
//! Decodes handshake messages from arbitrary bytes and runs validation,
//! proof, and version/capability negotiation. All paths must return typed
//! errors, never panic.

#![no_main]

use pico_guest_protocol::bootstrap_v1::{CapabilitySet, GuestHello, HostHello, HostReply};
use pico_guest_protocol::handshake::{
    HandshakeConfig, compute_guest_proof, negotiate_version_and_capabilities,
    validate_guest_hello,
};
use pico_core::crypto;
use libfuzzer_sys::fuzz_target;
use prost::Message;

fn fuzz_one(data: &[u8]) {
    // Try every handshake message shape.
    if let Ok(guest) = GuestHello::decode(data) {
        let config = HandshakeConfig {
            sandbox_id: "sbx_fuzz".into(),
            image_id: String::new(),
            image_digest: String::new(),
            ..Default::default()
        };
        let secret = crypto::derive_handshake_shared_secret(&config.sandbox_id);
        let nonce = crypto::generate_nonce();
        let _ = validate_guest_hello(&config, &guest, &secret, &nonce);
        let _ = compute_guest_proof(&secret, &nonce, &guest);
        let _ = negotiate_version_and_capabilities(
            &config,
            &guest.supported_versions,
            guest.guest_capabilities.as_ref(),
        );
    }
    if let Ok(host) = HostHello::decode(data) {
        // HostHello fields feed negotiation as guest ranges in reflection.
        let config = HandshakeConfig::default();
        let caps = host.host_capabilities.as_ref().map(|c| CapabilitySet {
            identifiers: c.identifiers.clone(),
        });
        let _ = negotiate_version_and_capabilities(&config, &host.supported_versions, caps.as_ref());
    }
    let _ = HostReply::decode(data);
}

fuzz_target!(|data: &[u8]| {
    fuzz_one(data);
});
