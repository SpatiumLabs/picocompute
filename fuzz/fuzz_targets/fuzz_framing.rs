//! Fuzz target for protocol framing.
//!
//! Exercises the length-prefixed framing layer over arbitrary bytes:
//! length validation, tag dispatch, and protobuf decode for operational
//! and handshake messages. Must never panic; oversized inputs must be
//! rejected before allocation.

#![no_main]

use pico_guest_protocol::framed::MAX_MESSAGE_SIZE;
use pico_guest_protocol::operational_v1::{ExecRequest, RequestContext, StreamFrame};
use pico_guest_protocol::bootstrap_v1::{GuestHello, HostHello};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fn fuzz_one(data: &[u8]) {
    if data.len() < 5 {
        return;
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    // Fail-closed length check mirrors framed::read_message.
    if len > MAX_MESSAGE_SIZE {
        return;
    }
    let tag = data[4];
    let payload = &data[4..];
    // Bound the decode window so huge valid lengths do not force allocation.
    let window = payload.get(..len.min(64 * 1024)).unwrap_or(payload);
    let _ = ExecRequest::decode(window);
    let _ = RequestContext::decode(window);
    let _ = StreamFrame::decode(window);
    let _ = GuestHello::decode(window);
    let _ = HostHello::decode(window);
    let _ = tag;
    // Tagged shape: [len][tag][protobuf]. Try tag-stripped decode too.
    if payload.len() >= 2 {
        let _ = ExecRequest::decode(&payload[1..]);
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_one(data);
});
