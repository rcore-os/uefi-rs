//! MTFTP4 protocol.

use super::*;
use crate::{
    proto::Protocol, table::runtime::Time, unsafe_guid, Completion, Event, Result, Status,
};

/// The MTFTP (Multicast Trivial File Transfer Protocol) Protocol.
///
/// This protocol is designed to be used by UEFI drivers and applications
/// to transmit and receive data files. The EFI MTFTPv4 Protocol driver uses
/// the underlying EFI UDPv4 Protocol driver and EFI IPv4 Protocol driver.
#[repr(C)]
#[unsafe_guid("78247c57-63db-4708-99c2-a8b4a9a61f6b")]
#[derive(Protocol)]
pub struct Mtftp4 {
    get_mode_data: extern "efiapi" fn(this: &mut Self, mode_data: *mut ModeData) -> Status,
    configure: extern "efiapi" fn(this: &mut Self, config_data: *const ConfigData) -> Status,
    get_info: extern "efiapi" fn(
        this: &mut Self,
        override_data: *const OverrideData,
        filename: *const u8,
        mode_str: *const u8,
        option_count: u8,
        option_list: *const OptionPair,
        packet_len: &mut u32,
        packet: &mut *mut Packet,
    ) -> Status,
    parse_options: usize,
    read_file: extern "efiapi" fn(this: &mut Self, token: &mut Token) -> Status,
    write_file: extern "efiapi" fn(this: &mut Self, token: &mut Token) -> Status,
    read_directory: extern "efiapi" fn(this: &mut Self, token: &mut Token) -> Status,
    poll: extern "efiapi" fn(this: &mut Self) -> Status,
}

impl Mtftp4 {
    /// Submits an asynchronous interrupt transfer to an interrupt endpoint of a USB device.
    pub fn get_mode_data(&mut self) -> Result<ModeData> {
        let mut mode_data = core::mem::MaybeUninit::uninit();
        (self.get_mode_data)(self, mode_data.as_mut_ptr())
            .into_with_val(|| unsafe { mode_data.assume_init() })
    }

    /// Initializes or changes the default operational setting.
    ///
    /// # Errors
    /// - SUCCESS           The EFI MTFTPv4 Protocol driver was configured successfully.
    /// - INVALID_PARAMETER One or more parameters are invalid.
    /// - ACCESS_DENIED     The EFI configuration could not be changed at this time because
    ///                     there is one MTFTP background operation in progress.
    /// - NO_MAPPING        When using a default address, configuration (DHCP, BOOTP,
    ///                     RARP, etc.) has not finished yet.
    /// - UNSUPPORTED       A configuration protocol (DHCP, BOOTP, RARP, etc.) could not
    ///                     be located when clients choose to use the default address settings.
    /// - OUT_OF_RESOURCES  The EFI MTFTPv4 Protocol driver instance data could not be allocated.
    /// - DEVICE_ERROR      An unexpected system or network error occurred. The EFI
    ///                     MTFTPv4 Protocol driver instance is not configured.
    pub fn configure(&mut self, config: &ConfigData) -> Result {
        (self.configure)(self, config).into()
    }

    /// Resets the operational parameters for this instance.
    pub fn reset(&mut self) -> Result {
        (self.configure)(self, core::ptr::null()).into()
    }

    /// Gets information about a file from an MTFTPv4 server.
    ///
    /// # Errors
    /// - SUCCESS              An MTFTPv4 OACK packet was received and is in the Packet.
    /// - INVALID_PARAMETER    One or more of the following conditions is TRUE:
    ///                        - This is NULL.
    ///                        - Filename is NULL.
    ///                        - OptionCount is not zero and OptionList is NULL.
    ///                        - One or more options in OptionList have wrong format.
    ///                        - PacketLength is NULL.
    ///                        - One or more IPv4 addresses in OverrideData are not valid
    ///                          unicast IPv4 addresses if OverrideData is not NULL.
    /// - UNSUPPORTED          One or more options in the OptionList are in the
    /// -                      unsupported list of structure EFI_MTFTP4_MODE_DATA.
    /// - NOT_STARTED          The EFI MTFTPv4 Protocol driver has not been started.
    /// - NO_MAPPING           When using a default address, configuration (DHCP, BOOTP,
    /// -                      RARP, etc.) has not finished yet.
    /// - ACCESS_DENIED        The previous operation has not completed yet.
    /// - OUT_OF_RESOURCES     Required system resources could not be allocated.
    /// - TFTP_ERROR           An MTFTPv4 ERROR packet was received and is in the Packet.
    /// - NETWORK_UNREACHABLE  An ICMP network unreachable error packet was received and the Packet is set to NULL.
    /// - HOST_UNREACHABLE     An ICMP host unreachable error packet was received and the Packet is set to NULL.
    /// - PROTOCOL_UNREACHABLE An ICMP protocol unreachable error packet was received and the Packet is set to NULL.
    /// - PORT_UNREACHABLE     An ICMP port unreachable error packet was received and the Packet is set to NULL.
    /// - ICMP_ERROR           Some other ICMP ERROR packet was received and is in the Buffer.
    /// - PROTOCOL_ERROR       An unexpected MTFTPv4 packet was received and is in the Packet.
    /// - TIMEOUT              No responses were received from the MTFTPv4 server.
    /// - DEVICE_ERROR         An unexpected network error or system error occurred.
    /// - NO_MEDIA             There was a media error.
    pub fn get_info<'a>(
        &mut self,
        override_data: Option<&OverrideData>,
        filename: &str,
        mode_str: Option<&str>,
        options: &[OptionPair],
    ) -> Result<&'a mut [u8]> {
        let mut packet_len: u32 = 0;
        let mut packet: *mut Packet = core::ptr::null_mut();
        (self.get_info)(
            self,
            override_data.map(|p| p as _).unwrap_or(core::ptr::null()),
            filename.as_ptr(),
            mode_str.map(|p| p.as_ptr()).unwrap_or(core::ptr::null()),
            options.len() as u8,
            options.as_ptr(),
            &mut packet_len,
            &mut packet,
        )
        .into_with_val(|| unsafe { core::slice::from_raw_parts_mut(packet, packet_len as usize) })
    }

    /// Downloads a file from an MTFTPv4 server. (blocking)
    ///
    /// # Errors
    /// - SUCCESS              The data file has been transferred successfully.
    /// - OUT_OF_RESOURCES     Required system resources could not be allocated.
    /// - BUFFER_TOO_SMALL     BufferSize is not zero but not large enough to hold the
    ///                        downloaded data in downloading process.
    /// - ABORTED              Current operation is aborted by user.
    /// - NETWORK_UNREACHABLE  An ICMP network unreachable error packet was received.
    /// - HOST_UNREACHABLE     An ICMP host unreachable error packet was received.
    /// - PROTOCOL_UNREACHABLE An ICMP protocol unreachable error packet was received.
    /// - PORT_UNREACHABLE     An ICMP port unreachable error packet was received.
    /// - ICMP_ERROR           Some other ICMP ERROR packet was received.
    /// - TIMEOUT              No responses were received from the MTFTPv4 server.
    /// - TFTP_ERROR           An MTFTPv4 ERROR packet was received.
    /// - DEVICE_ERROR         An unexpected network error or system error occurred.
    /// - NO_MEDIA             There was a media error.
    pub fn read_file(&mut self, filename: &str, buf: &mut [u8]) -> Result<u64> {
        let mut token = Token {
            filename: filename.as_ptr(),
            buffer: buf.as_mut_ptr(),
            buffer_size: buf.len() as u64,
            ..unsafe { core::mem::zeroed() }
        };
        (self.read_file)(self, &mut token).into_with_val(|| token.buffer_size)
    }

    /// Sends a file to an MTFTPv4 server. (blocking)
    ///
    /// # Errors
    /// - SUCCESS           The upload session has started.
    /// - UNSUPPORTED       The operation is not supported by this implementation.
    /// - INVALID_PARAMETER One or more parameters are invalid.
    /// - UNSUPPORTED       One or more options in the Token.OptionList are in
    ///                     the unsupported list of structure EFI_MTFTP4_MODE_DATA.
    /// - NOT_STARTED       The EFI MTFTPv4 Protocol driver has not been started.
    /// - NO_MAPPING        When using a default address, configuration (DHCP, BOOTP,
    ///                     RARP, etc.) is not finished yet.
    /// - ALREADY_STARTED   This Token is already being used in another MTFTPv4 session.
    /// - OUT_OF_RESOURCES  Required system resources could not be allocated.
    /// - ACCESS_DENIED     The previous operation has not completed yet.
    /// - DEVICE_ERROR      An unexpected network error or system error occurred.
    pub fn write_file(&mut self, filename: &str, buf: &[u8]) -> Result {
        let mut token = Token {
            filename: filename.as_ptr(),
            buffer: buf.as_ptr() as _,
            buffer_size: buf.len() as u64,
            ..unsafe { core::mem::zeroed() }
        };
        (self.write_file)(self, &mut token).into()
    }

    /// Polls for incoming data packets and processes outgoing data packets.
    ///
    /// # Errors
    /// - EFI_SUCCESS           Incoming or outgoing data was processed.
    /// - EFI_NOT_STARTED       This EFI MTFTPv4 Protocol instance has not been started.
    /// - EFI_NO_MAPPING        When using a default address, configuration (DHCP, BOOTP,
    ///                         RARP, etc.) is not finished yet.
    /// - EFI_DEVICE_ERROR      An unexpected system or network error occurred.
    /// - EFI_TIMEOUT           Data was dropped out of the transmit and/or receive queue.
    ///                         Consider increasing the polling rate.
    pub fn poll(&mut self) -> Result {
        (self.poll)(self).into()
    }
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct ConfigData {
    pub use_default_setting: bool,
    pub station_ip: Ipv4Address,
    pub subnet_mask: Ipv4Address,
    pub local_port: u16,
    pub gateway_ip: Ipv4Address,
    pub server_ip: Ipv4Address,
    pub initial_server_port: u16,
    pub try_count: u16,
    pub timeout_value: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct ModeData {
    pub config_data: ConfigData,
    pub supported_option_count: u8,
    pub supported_options: *mut *mut u8,
    pub unsupported_option_count: u8,
    pub unsupported_options: *mut *mut u8,
}

#[repr(C)]
struct Token {
    /// The status that is returned to the caller at the end of the operation
    /// to indicate whether this operation completed successfully.
    status: Status,

    /// The event that will be signaled when the operation completes. If
    /// set to NULL, the corresponding function will wait until the read or
    /// write operation finishes. The type of Event must be
    /// EVT_NOTIFY_SIGNAL. The Task Priority Level (TPL) of
    /// Event must be lower than or equal to TPL_CALLBACK.
    event: Event,

    /// If not NULL, the data that will be used to override the existing configure data.
    override_data: *const OverrideData,

    /// The pointer to the null-terminated ASCII file name string.
    filename: *const u8,

    /// The pointer to the null-terminated ASCII mode string. If NULL, "octet" is used.
    mode_str: *const u8,

    /// Number of option/value string pairs.
    option_count: u32,

    /// The pointer to an array of option/value string pairs. Ignored if `option_count` is zero.
    option_list: *const OptionPair,

    /// The size of the data buffer.
    buffer_size: u64,

    /// The pointer to the data buffer.
    ///
    /// Data that is downloaded from the MTFTPv4 server is stored here.
    /// Data that is uploaded to the MTFTPv4 server is read from here.
    /// Ignored if BufferSize is zero.
    buffer: *mut u8,

    /// The pointer to the context that will be used by CheckPacket,
    /// TimeoutCallback and PacketNeeded.
    context: *mut u8,

    /// The pointer to the callback function to check the contents of the received packet.
    check_packet: extern "efiapi" fn(
        this: &mut Mtftp4,
        token: &mut Token,
        packet_len: u16,
        packet: *mut Packet,
    ) -> Status,

    /// The pointer to the function to be called when a timeout occurs.
    timeout_callback: extern "efiapi" fn(this: &mut Mtftp4, token: &mut Token) -> Status,

    /// The pointer to the function to provide the needed packet contents.
    packet_needed: extern "efiapi" fn(
        this: &mut Mtftp4,
        token: &mut Token,
        out_len: &mut u16,
        out_buf: &mut *mut u8,
    ) -> Status,
}

impl Default for Token {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
pub struct OptionPair {
    pub option: *const u8,
    pub value: *const u8,
}

type Packet = u8;

#[repr(C)]
#[derive(Debug, Default)]
pub struct OverrideData {
    pub gateway_ip: Ipv4Address,
    pub server_ip: Ipv4Address,
    pub server_port: u16,
    pub try_count: u16,
    pub timeout_value: u16,
}

struct ReadFileToken {
    token: Token,
}

impl ReadFileToken {
    pub fn new() -> Self {
        ReadFileToken {
            token: Token::default(),
        }
    }

    pub fn status(&self) -> Status {
        self.token.status
    }

    pub fn set_buffer(&mut self, buf: &mut [u8]) {
        self.token.buffer_size = buf.len() as u64;
        self.token.buffer = buf.as_mut_ptr();
    }

    pub fn set_filename(&mut self, name: &str) {
        self.token.filename = name.as_ptr();
    }
}
