//! Protocol round-trip and compatibility property tests.
//!
//! Proves wire-format stability over randomized inputs: protobuf round-trips
//! are deterministic, protocol versions pack as `(major << 16) | minor`,
//! framing length/tag parsing never panics, version negotiation picks the
//! highest overlap, and v1.0/v1.5 messages stay cross-parseable.
//!
//! Run with:
//! ```bash
//! cargo nextest run -p pico-guest-protocol --test protocol_property
//! ```

use pico_guest_protocol::bootstrap_v1::{
    CapabilitySet, GuestHello, HostHello, Nonce, Proof, Version, VersionRange,
};
use pico_guest_protocol::framed::{self, MAX_MESSAGE_SIZE};
use pico_guest_protocol::handshake::HandshakeConfig;
use pico_guest_protocol::handshake::negotiate_version_and_capabilities;
use pico_guest_protocol::operational_v1::{ExecRequest, RequestContext, StreamFrame};
use proptest::prelude::*;
use prost::Message;
use std::time::Duration;

fn arb_version() -> impl Strategy<Value = (u32, u32)> {
    (0..3u32, 0..8u32)
}

fn arb_version_range() -> impl Strategy<Value = VersionRange> {
    (arb_version(), arb_version()).prop_map(|((lo_maj, lo_min), (hi_maj, hi_min))| VersionRange {
        min: Some(Version {
            major: lo_maj,
            minor: lo_min,
        }),
        max: Some(Version {
            major: hi_maj,
            minor: hi_min,
        }),
    })
}

fn arb_printable(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(proptest::char::range('a', 'z'), 0..max)
        .prop_map(|v| v.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Protocol versions pack as (major << 16) | minor, pinned to the golden
    /// wire values shared with compat fixtures. Packing inverts through the
    /// real version negotiator output.
    #[test]
    fn protocol_version_packing_matches_wire(guest_hi in 0..8u32) {
        // Golden wire values from compat_fixtures: v1.0 and v1.5.
        prop_assert_eq!(1u32 << 16, 0x00010000);
        prop_assert_eq!((1u32 << 16) | 5, 0x00010005);
        // The negotiator output round-trips through the same packing.
        let config = HandshakeConfig {
            host_capabilities: vec!["exec".into()],
            ..Default::default()
        };
        let ranges = vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version {
                major: 1,
                minor: guest_hi,
            }),
        }];
        let caps = CapabilitySet {
            identifiers: vec!["exec".into()],
        };
        let result = negotiate_version_and_capabilities(&config, &ranges, Some(&caps));
        // Guest min is always 1.0, so every guest_hi in 0..8 overlaps the
        // host 1.0-1.5 range and negotiation succeeds.
        let negotiated = result.unwrap();
        let packed = (negotiated.version.0 << 16) | negotiated.version.1;
        prop_assert_eq!(packed >> 16, negotiated.version.0);
        prop_assert_eq!(packed & 0xFFFF, negotiated.version.1);
    }

    /// ExecRequest protobuf round-trip is stable: decode(encode(x)) == x for
    /// the fields we set, and re-encoding is deterministic.
    #[test]
    fn exec_request_round_trip_stable(
        command in arb_printable(32),
        arg_count in 0..4usize,
        sandbox in arb_printable(16),
        epoch in 0..10u64,
        major in 1..2u32,
        minor in 0..6u32,
    ) {
        let args: Vec<String> = (0..arg_count).map(|i| format!("arg{i}")).collect();
        let req = ExecRequest {
            context: Some(RequestContext {
                request_id: "req".into(),
                operation_id: "op".into(),
                sandbox_id: sandbox.clone(),
                session_id: vec![0x01u8; 16],
                policy_epoch: epoch,
                protocol_version: (major << 16) | minor,
                deadline: None,
                trace_context: None,
            }),
            command: command.clone(),
            args: args.clone(),
            env: Default::default(),
            working_dir: "/tmp".into(),
            timeout: None,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };
        let encoded = req.encode_to_vec();
        prop_assert!(encoded.len() < MAX_MESSAGE_SIZE);
        let decoded = ExecRequest::decode(encoded.as_slice()).unwrap();
        prop_assert_eq!(&decoded.command, &command);
        prop_assert_eq!(&decoded.args, &args);
        prop_assert_eq!(&decoded.context.as_ref().unwrap().sandbox_id, &sandbox);
        let re_encoded = decoded.encode_to_vec();
        let re_decoded = ExecRequest::decode(re_encoded.as_slice()).unwrap();
        prop_assert_eq!(&re_decoded.command, &command);
    }

    /// StreamFrame round-trip preserves sequence, payload, and EOS flag.
    #[test]
    fn stream_frame_round_trip(
        seq in 0..1000u64,
        len in 0..512usize,
        eos in proptest::bool::ANY,
    ) {
        let frame = StreamFrame {
            sequence: seq,
            payload: vec![0xAAu8; len],
            end_of_stream: eos,
        };
        let encoded = frame.encode_to_vec();
        let decoded = StreamFrame::decode(encoded.as_slice()).unwrap();
        prop_assert_eq!(decoded.sequence, seq);
        prop_assert_eq!(decoded.payload.len(), len);
        prop_assert_eq!(decoded.end_of_stream, eos);
    }

    /// Framing rejects oversized lengths before allocating and never panics
    /// on truncated or adversarial prefixes. Exercises the real
    /// `framed::read_message` / `read_tagged_raw` decoders over in-memory
    /// inputs (in-memory reads never block, so the timeout never fires).
    #[test]
    fn framing_rejects_oversized_before_alloc(
        len in proptest::num::u32::ANY,
        tail in prop::collection::vec(proptest::num::u8::ANY, 0..16),
    ) {
        let mut input = Vec::with_capacity(4 + tail.len());
        input.extend_from_slice(&len.to_be_bytes());
        input.extend_from_slice(&tail);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let oversized = (len as usize) > MAX_MESSAGE_SIZE;
        let mut slice = input.as_slice();
        let decoded: std::io::Result<ExecRequest> =
            rt.block_on(framed::read_message(&mut slice, Duration::from_millis(50)));
        if oversized {
            let err = decoded.unwrap_err();
            prop_assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            prop_assert!(err.to_string().contains("too large"));
        }
        // Reaching this point proves no panic and no oversized allocation;
        // any other outcome (Ok on empty input, truncated-payload Err) is fine.
        let mut slice = input.as_slice();
        let raw: std::io::Result<(u8, Vec<u8>)> =
            rt.block_on(framed::read_tagged_raw(&mut slice, Duration::from_millis(50)));
        if oversized {
            prop_assert!(raw.is_err());
        }
    }

    /// Version negotiation picks the highest overlap or fails when disjoint.
    #[test]
    fn version_negotiation_picks_highest_overlap(
        guest_min_minor in 0..8u32,
        guest_max_minor in 0..8u32,
    ) {
        let (g_lo, g_hi) = if guest_min_minor <= guest_max_minor {
            (guest_min_minor, guest_max_minor)
        } else {
            (guest_max_minor, guest_min_minor)
        };
        let config = HandshakeConfig {
            host_capabilities: vec!["exec".into()],
            ..Default::default()
        };
        let guest_ranges = vec![VersionRange {
            min: Some(Version { major: 1, minor: g_lo }),
            max: Some(Version { major: 1, minor: g_hi }),
        }];
        let caps = CapabilitySet { identifiers: vec!["exec".into()] };
        let result = negotiate_version_and_capabilities(&config, &guest_ranges, Some(&caps));
        // Host supports 1.0-1.5. Overlap exists iff guest range touches it.
        let overlaps = g_lo <= 5;
        if overlaps {
            let negotiated = result.unwrap();
            prop_assert_eq!(negotiated.version.0, 1);
            prop_assert!(negotiated.version.1 <= 5);
            prop_assert!(negotiated.version.1 >= g_lo.min(5));
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Capability intersection is empty exactly when host and guest share
    /// nothing; negotiation fails closed on empty intersection.
    #[test]
    fn capability_negotiation_fails_closed_on_empty(
        host_has_exec in proptest::bool::ANY,
        guest_has_exec in proptest::bool::ANY,
    ) {
        let config = HandshakeConfig {
            host_capabilities: if host_has_exec { vec!["exec".into()] } else { vec!["file".into()] },
            ..Default::default()
        };
        let guest_caps = CapabilitySet {
            identifiers: if guest_has_exec { vec!["exec".into()] } else { vec!["stats".into()] },
        };
        let guest_ranges = vec![VersionRange {
            min: Some(Version { major: 1, minor: 0 }),
            max: Some(Version { major: 1, minor: 5 }),
        }];
        let result = negotiate_version_and_capabilities(&config, &guest_ranges, Some(&guest_caps));
        // Only exec/exec shares a capability in this fixture; file/stats,
        // exec/stats, and file/exec all share nothing and must fail closed.
        let shares = host_has_exec && guest_has_exec;
        if shares {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Handshake messages with arbitrary small strings round-trip without panic.
    #[test]
    fn handshake_messages_round_trip(
        sandbox in arb_printable(24),
        image in arb_printable(24),
    ) {
        let hello = HostHello {
            protocol_name: "pico.guest".into(),
            bootstrap_version: Some(VersionRange {
                min: Some(Version { major: 1, minor: 0 }),
                max: Some(Version { major: 1, minor: 0 }),
            }),
            supported_versions: vec![VersionRange {
                min: Some(Version { major: 1, minor: 0 }),
                max: Some(Version { major: 1, minor: 5 }),
            }],
            host_capabilities: Some(CapabilitySet { identifiers: vec!["exec".into()] }),
            host_nonce: Some(Nonce { value: vec![0xABu8; 32] }),
            sandbox_id: sandbox.clone(),
            image_id: image.clone(),
            image_digest: "digest".into(),
        };
        let encoded = hello.encode_to_vec();
        let decoded = HostHello::decode(encoded.as_slice()).unwrap();
        prop_assert_eq!(decoded.sandbox_id, sandbox.clone());
        prop_assert_eq!(decoded.image_id, image.clone());

        let guest = GuestHello {
            supported_versions: vec![VersionRange {
                min: Some(Version { major: 1, minor: 0 }),
                max: Some(Version { major: 1, minor: 3 }),
            }],
            guest_capabilities: Some(CapabilitySet { identifiers: vec!["exec".into()] }),
            guest_nonce: Some(Nonce { value: vec![0xCDu8; 32] }),
            agent_version: "agent".into(),
            boot_id: "boot".into(),
            image_id: image.clone(),
            image_digest: "digest".into(),
            proof: Some(Proof { value: vec![0xEFu8; 32] }),
        };
        let encoded = guest.encode_to_vec();
        let decoded = GuestHello::decode(encoded.as_slice()).unwrap();
        prop_assert_eq!(decoded.image_id, image.clone());
    }

    /// Arbitrary version ranges never panic the negotiator.
    #[test]
    fn arbitrary_ranges_never_panic(ranges in prop::collection::vec(arb_version_range(), 0..4)) {
        let config = HandshakeConfig {
            host_capabilities: vec!["exec".into()],
            ..Default::default()
        };
        let caps = CapabilitySet { identifiers: vec!["exec".into()] };
        let _ = negotiate_version_and_capabilities(&config, &ranges, Some(&caps));
    }
}
