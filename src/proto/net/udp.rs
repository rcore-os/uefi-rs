//! UDP protocol.

use super::*;
use crate::{
    proto::Protocol, table::runtime::Time, unsafe_guid, Completion, Event, Result, Status,
};

/// The UDP (User Datagram Protocol) Protocol.
#[repr(C)]
#[unsafe_guid("3ad9df29-4501-478d-b1f8-7f7fe70e50f3")]
#[derive(Protocol)]
pub struct Udp4 {
    get_mode_data: extern "efiapi" fn(
        this: &mut Self,
        udp4_config_data: *mut ConfigData,
        ip4_mode_data: *mut ModeData,
        mnp_config_data: *mut ManagedNetworkConfigData,
        smp_mode_data: *mut SimpleNetworkMode,
    ) -> Status,
    configure: extern "efiapi" fn(this: &mut Self, config_data: *const ConfigData) -> Status,
    groups: extern "efiapi" fn(
        this: &mut Self,
        join_flag: bool,
        multicast_address: *const Ipv4Address,
    ) -> Status,
    routes: extern "efiapi" fn(
        this: &mut Self,
        delete_route: bool,
        subnet_address: &Ipv4Address,
        subnet_mask: &Ipv4Address,
        gateway_address: &Ipv4Address,
    ) -> Status,
    transmit: extern "efiapi" fn(this: &mut Self, token: &mut CompletionToken) -> Status,
    receive: extern "efiapi" fn(this: &mut Self, token: &mut CompletionToken) -> Status,
    cancel: extern "efiapi" fn(this: &mut Self, token: &mut CompletionToken) -> Status,
    poll: extern "efiapi" fn(this: &mut Self) -> Status,
}

impl Udp4 {
    /// Reads the current operational settings.
    ///
    /// This function copies the current operational settings of this EFI
    /// UDPv4 Protocol instance into user-supplied buffers. This function is used
    /// optionally to retrieve the operational mode data of underlying networks or drivers.
    pub fn get_mode_data(&mut self) -> Result<ConfigData> {
        let mut config = core::mem::MaybeUninit::uninit();
        (self.get_mode_data)(
            self,
            config.as_mut_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
        .into_with_val(|| unsafe { config.assume_init() })
    }

    /// Initializes, changes, or resets the operational parameters for this instance
    /// of the EFI UDPv4 Protocol.
    ///
    /// This function is used to do the following:
    /// * Initialize and start this instance of the EFI UDPv4 Protocol.
    /// * Change the filtering rules and operational parameters.
    ///
    /// Until these parameters are initialized, no network traffic can be sent or
    /// received by this instance.
    /// With different parameters in `config`, `configure()` can be used to bind
    /// this instance to specified port.
    ///
    /// # Errors
    /// - SUCCESS           The configuration settings were set, changed, or reset successfully.
    /// - NO_MAPPING        When using a default address, configuration (DHCP, BOOTP,RARP, etc.)
    ///                     is not finished yet.
    /// - INVALID_PARAMETER This is NULL.
    /// - INVALID_PARAMETER UdpConfigData.StationAddress is not a valid unicast IPv4 address.
    /// - INVALID_PARAMETER UdpConfigData.SubnetMask is not a valid IPv4 address mask. The subnet
    ///                     mask must be contiguous.
    /// - INVALID_PARAMETER UdpConfigData.RemoteAddress is not a valid unicast IPv4 address if it
    ///                     is not zero.
    /// - ALREADY_STARTED   The EFI UDPv4 Protocol instance is already started/configured
    ///                     and must be stopped/reset before it can be reconfigured.
    /// - ACCESS_DENIED     UdpConfigData. AllowDuplicatePort is FALSE
    ///                     and UdpConfigData.StationPort is already used by
    ///                     other instance.
    /// - OUT_OF_RESOURCES  The EFI UDPv4 Protocol driver cannot allocate memory for this
    ///                     EFI UDPv4 Protocol instance.
    /// - DEVICE_ERROR      An unexpected network or system error occurred and this instance
    ///                     was not opened.
    pub fn configure(&mut self, config: &ConfigData) -> Result {
        (self.configure)(self, config).into()
    }

    /// Resets the operational parameters for this instance.
    ///
    /// Once reset, the receiving queue and transmitting queue are flushed
    /// and no traffic is allowed through this instance.
    pub fn reset(&mut self) -> Result {
        (self.configure)(self, core::ptr::null()).into()
    }

    /// Joins multicast group.
    pub fn join_multicast_group(&mut self, addr: Ipv4Address) -> Result {
        (self.groups)(self, true, &addr).into()
    }

    /// Leaves all multicast groups.
    pub fn leave_multicast_groups(&mut self) -> Result {
        (self.groups)(self, false, core::ptr::null()).into()
    }

    /// Adds and deletes routing table entries.
    ///
    /// The Routes() function adds a route to or deletes a route from the routing table.
    /// Routes are determined by comparing the SubnetAddress with the destination IP
    /// address and arithmetically AND-ing it with the SubnetMask. The gateway address
    /// must be on the same subnet as the configured station address.
    ///
    /// The default route is added with SubnetAddress and SubnetMask both set to 0.0.0.0.
    /// The default route matches all destination IP addresses that do not match any
    /// other routes.
    ///
    /// A zero GatewayAddress is a nonroute. Packets are sent to the destination IP
    /// address if it can be found in the Address Resolution Protocol (ARP) cache or
    /// on the local subnet. One automatic nonroute entry will be inserted into the
    /// routing table for outgoing packets that are addressed to a local subnet
    /// (gateway address of 0.0.0.0).
    ///
    /// Each instance of the EFI UDPv4 Protocol has its own independent routing table.
    /// Instances of the EFI UDPv4 Protocol that use the default IP address will also
    /// have copies of the routing table provided by the EFI_IP4_CONFIG_PROTOCOL. These
    /// copies will be updated automatically whenever the IP driver reconfigures its
    /// instances; as a result, the previous modification to these copies will be lost.
    fn routes(&mut self) -> Result {
        unimplemented!()
    }

    /// Queues outgoing data packets into the transmit queue.
    ///
    /// This function places a sending request to this instance of the EFI
    /// UDPv4 Protocol, alongside the transmit data that was filled by the user. Whenever
    /// the packet in the token is sent out or some errors occur, the Token.Event will
    /// be signaled and Token.Status is updated. Providing a proper notification function
    /// and context for the event will enable the user to receive the notification and
    /// transmitting status.
    ///
    /// # Errors
    /// - SUCCESS           The data has been queued for transmission.
    /// - NOT_STARTED       This EFI UDPv4 Protocol instance has not been started.
    /// - NO_MAPPING        When using a default address, configuration (DHCP, BOOTP,
    ///                     RARP, etc.) is not finished yet.
    /// - INVALID_PARAMETER One or more parameters are invalid.
    /// - ACCESS_DENIED     The transmit completion token with the same
    ///                     Token.Event was already in the transmit queue.
    /// - NOT_READY         The completion token could not be queued because the
    ///                     transmit queue is full.
    /// - OUT_OF_RESOURCES  Could not queue the transmit data.
    /// - NOT_FOUND         There is no route to the destination network or address.
    /// - BAD_BUFFER_SIZE   The data length is greater than the maximum UDP packet
    ///                     size. Or the length of the IP header + UDP header + data
    ///                     length is greater than MTU if DoNotFragment is TRUE.
    pub fn transmit(&mut self, token: &mut CompletionToken) -> Result {
        (self.transmit)(self, token).into()
    }

    /// Places an asynchronous receive request into the receiving queue.
    ///
    /// This function places a completion token into the receive packet queue.
    /// This function is always asynchronous.
    ///
    /// The caller must fill in the Token.Event field in the completion token, and this
    /// field cannot be NULL. When the receive operation completes, the EFI UDPv4 Protocol
    /// driver updates the Token.Status and Token.Packet.RxData fields and the Token.Event
    /// is signaled. Providing a proper notification function and context for the event
    /// will enable the user to receive the notification and receiving status. That
    /// notification function is guaranteed to not be re-entered.
    pub fn receive(&mut self, token: &mut CompletionToken) -> Result {
        (self.receive)(self, token).into()
    }

    /// Aborts an asynchronous transmit or receive request.
    ///
    /// This function is used to abort a pending transmit or receive request.
    ///
    /// If the token is in the transmit or receive request queues, after calling this
    /// function, Token.Status will be set to EFI_ABORTED and then Token.Event will be
    /// signaled. If the token is not in one of the queues, which usually means that
    /// the asynchronous operation has completed, this function will not signal the
    /// token and EFI_NOT_FOUND is returned.
    pub fn cancel(&mut self, token: &mut CompletionToken) -> Result {
        (self.cancel)(self, token).into()
    }

    /// Polls for incoming data packets and processes outgoing data packets.
    ///
    /// This function can be used by network drivers and applications to increase
    /// the rate that data packets are moved between the communications device and the
    /// transmit and receive queues.
    ///
    /// In some systems, the periodic timer event in the managed network driver may not
    /// poll the underlying communications device fast enough to transmit and/or receive
    /// all data packets without missing incoming packets or dropping outgoing packets.
    ///
    /// Drivers and applications that are experiencing packet loss should try calling
    /// the `poll()` function more often.
    pub fn poll(&mut self) -> Result {
        (self.poll)(self).into()
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct ConfigData {
    // Receiving Filters
    pub accept_broadcast: bool,
    pub accept_promiscuous: bool,
    pub accept_any_port: bool,
    pub allow_duplicate_port: bool,

    // I/O parameters
    pub type_of_service: u8,
    pub time_to_live: u8,
    pub do_not_fragment: bool,
    pub receive_timeout: u32,
    pub transmit_timeout: u32,

    // Access Point
    pub use_default_address: bool,
    pub station_address: Ipv4Address,
    pub subnet_mask: Ipv4Address,
    pub station_port: u16,
    pub remote_address: Ipv4Address,
    pub remote_port: u16,
}

#[repr(C)]
struct ModeData {
    // TODO
}

#[repr(C)]
struct ManagedNetworkConfigData {
    // TODO
}

#[repr(C)]
struct SimpleNetworkMode {
    // TODO
}

#[repr(C)]
pub struct SessionData {
    pub src_addr: Ipv4Address,
    pub src_port: u16,
    pub dst_addr: Ipv4Address,
    pub dst_port: u16,
}

#[repr(C)]
pub struct FragmentData {
    pub length: u32,
    pub buffer: *mut u8,
}

#[repr(C)]
pub struct ReceiveData {
    pub timestamp: Time,
    pub recycle_signal: Event,
    pub session: SessionData,
    pub data_length: u32,
    pub fragment_count: u32,
    pub fragment_table: [FragmentData; 1],
}

#[repr(C)]
pub struct TransmitData {
    pub session: *mut SessionData,
    pub gateway_address: *mut Ipv4Address,
    pub data_length: u32,
    pub fragment_count: u32,
    pub fragment_table: [FragmentData; 1],
}

#[repr(C)]
pub struct CompletionToken {
    pub event: Event,
    pub status: Status,
    /// *mut ReceiveData or TransmitData
    pub packet: *mut u8,
}

// pub struct Token {
//     raw: Box<CompletionToken>,
// }
