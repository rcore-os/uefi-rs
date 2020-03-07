//! Network protocols.

pub mod udp;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    pub const fn from(a0: u8, a1: u8, a2: u8, a3: u8) -> Self {
        Ipv4Address([a0, a1, a2, a3])
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct Ipv6Address([u8; 16]);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct MacAddress([u8; 32]);
