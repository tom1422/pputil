use std::{net::Ipv4Addr, string::FromUtf8Error};
use strum_macros::EnumIter;
use bitflags::bitflags;

//Section is for constants used in transmission and testing purposes
//Flags are not needed because use is fixed and also automation is not needed

pub enum ProtoConsts {
    QueryRequest,
    TransmitRequest,
    QueryResponse,
    TransmitResponse,
    NDSP,
    Reserved,
    EndOfMessage,
    MACBroadcast,
    MACMyPC,
}

impl ProtoConsts {
    pub fn value(&self) -> &[u8] {
        match self {
            ProtoConsts::QueryRequest => &[0x01, 0x01],
            ProtoConsts::TransmitRequest => &[0x01, 0x03],
            ProtoConsts::QueryResponse => &[0x01, 0x02],
            ProtoConsts::TransmitResponse => &[0x10, 0x04],

            ProtoConsts::NDSP => &[0x4E, 0x53, 0x44, 0x50],
            ProtoConsts::Reserved => &[0x00, 0x00],
            ProtoConsts::EndOfMessage => &[0xFF, 0xFF, 0x00, 0x00],

            ProtoConsts::MACBroadcast => &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ProtoConsts::MACMyPC => &[0x4c, 0xcc, 0x6a, 0x6c, 0xce, 0x7e],
        }
    }
}

//
//Cmd section is for TLV commands which are sent to the switch and are processed.
//Stored as U32 allowing for lower 2 bytes being the command and upper 2 bytes being the flags
//

#[derive(Debug, Clone, EnumIter)]
#[repr(u32)]
pub enum Cmd {
    CMD_Model = u32([0x00, 0x01]),
    CMD_0002 = u32([0x00, 0x02]),
    CMD_Name = u32([0x00, 0x03]),
    CMD_Switch_MAC = u32([0x00, 0x04]),
    CMD_Location = u32([0x00, 0x05]),
    CMD_IPv4 = u32([0x00, 0x06]),
    CMD_Switch_Netmask = u32([0x00, 0x07]),
    CMD_Switch_Gateway = u32([0x00, 0x08]),
    CMD_Password = u32([0x00, 0x0a]) | CmdAttributes::WRITE_ONLY.bits(),
    CMD_Switch_DHCP = u32([0x00, 0x0b]),
    CMD_000C = u32([0x00, 0x0c]),
    CMD_FW_Version = u32([0x00, 0x0d]),
    CMD_FW_Version_2 = u32([0x00, 0x0e]),
    CMD_FW_Active = u32([0x00, 0x0f]),

    CMD_0014 = u32([0x00, 0x14]), //Usually 4 bytes like 00 00 00 01

    CMD_0C00 = u32([0x0C, 0x00]), //Response: n copies of 3 byte TLVs where n is port count
    CMD_1000 = u32([0x10, 0x00]), //Response: n copies of 49 byte TLVs where n is port count

    CMD_2000 = u32([0x20, 0x00]), //Usually 1 byte like 00

    CMD_3400 = u32([0x34, 0x00]), //Usually 1 byte like 02

    CMD_4C00 = u32([0x4c, 0x00]), //Response: n copies of 5 byte TLVs where n is port count

    CMD_5000 = u32([0x50, 0x00]), //Response: n copies of 5 byte TLVs where n is port count
    CMD_5400 = u32([0x54, 0x00]), //Usually 1 byte like 00
    CMD_5C00 = u32([0x5c, 0x00]), //Usually 3 bytes like 00 00 00

    CMD_Port_Count = u32([0x60, 0x00]),

    CMD_6400 = u32([0x64, 0x00]), //Usually 2 bytes like 00 20
    CMD_6800 = u32([0x68, 0x00]), //Usually 4 bytes like 00 01 00 01
    CMD_6C00 = u32([0x6C, 0x00]), //Usually 1 byte like 00

    CMD_7000 = u32([0x70, 0x00]), //Usually 1 byte like 00
    CMD_7400 = u32([0x74, 0x00]), //Usually 8 bytes like 00 00 00 08 7f fc ff ff
    CMD_7800 = u32([0x78, 0x00]), //Usually 21 bytes like 01 30 30 31 31 31 31 31 31 31 31 31 31 31 00 00 1 20 10 00 a2
    CMD_7C00 = u32([0x7c, 0x00]), //Usually 1 byte like 01

    CMD_9000 = u32([0x90, 0x00]), //Usually 1 byte like 00
}

impl Cmd {
    pub fn is_flag_set(&self, flag: CmdAttributes) -> bool {
        flag.bits() == (self.clone() as u32 | flag.bits())
    }
}

impl Into<[u8; 2]> for Cmd {
    fn into(self) -> [u8; 2] {
        let raw = self as u16;
        (&[(raw >> 8) as u8, raw as u8]).clone()
    }
}

impl Into<[u8; 2]> for &Cmd {
    fn into(self) -> [u8; 2] {
        let raw = self.clone() as u16;
        (&[(raw >> 8) as u8, raw as u8]).clone()
    }
}

const fn u32(arr: [u8; 2]) -> u32 {
    (arr[0] as u32) << 8 | arr[1] as u32
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct CmdAttributes: u32 {
        const READ_ONLY = 0x00001111;
        const WRITE_ONLY = 0x01001111;
        const READ_WRITE = 0x10001111;
    }
}

//
//Section for defining how the TLVs should be laid out and how data conversion should happen
//e.g. certain commands may need converting to a string
//

#[derive(Debug)]
pub enum TLVReadingError {
    ArrTooShort(String),
    InvalidType(String),
    EndOfMessage,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TypeLengthValue {
    cmd: [u8; 2],
    len: u16,
    value: Vec<u8>,
}

impl TypeLengthValue {
    pub fn from_raw(raw: &[u8]) -> Result<(TypeLengthValue, usize), TLVReadingError> {
        if raw.len() < 4 {
            return Err(TLVReadingError::ArrTooShort(String::from(
                "Raw array too short for type/length",
            )));
        }

        if &raw[0..4] == ProtoConsts::EndOfMessage.value() {
            return Err(TLVReadingError::EndOfMessage);
        }

        let len_ar: [u8; 2] = raw[2..4].try_into().unwrap();
        let len: u16 = u16::from(len_ar[0]) << 8 | (len_ar[1] as u16);
        let len_index: usize = (len + 4).try_into().unwrap();

        if raw.len() < len_index {
            return Err(TLVReadingError::ArrTooShort(String::from(
                "Raw array too short for value",
            )));
        }

        Ok((
            TypeLengthValue {
                cmd: raw[0..2].try_into().unwrap(),
                len: len,
                value: Vec::from(&raw[4..len_index]),
            },
            len_index,
        ))
    }

    pub fn to_raw(&self) -> Vec<u8> {
        let mut final_cmd: Vec<u8> = Vec::new();
        final_cmd.append(&mut Vec::from(self.cmd));
        final_cmd.append(&mut Vec::from(self.len.to_be_bytes()));
        final_cmd.append(&mut self.value.clone());

        final_cmd
    }

    pub fn cmd_equal_to(&self, cmd: &Cmd) -> bool {
        if self.cmd == <&Cmd as Into<[u8; 2]>>::into(cmd) {
            return true;
        }
        false
    }
}

impl Default for TypeLengthValue {
    fn default() -> Self {
        Self {
            cmd: [0; 2],
            len: 0,
            value: Default::default(),
        }
    }
}

impl From<()> for TypeLengthValue {
    fn from(_: ()) -> Self {
        Self::default()
    }
}

impl From<Cmd> for TypeLengthValue {
    fn from(cmd_enum: Cmd) -> Self {
        Self {
            cmd: cmd_enum.into(),
            ..Self::default()
        }
    }
}

impl From<(Cmd, u16, Vec<u8>)> for TypeLengthValue {
    fn from((cmd_enum, len, value): (Cmd, u16, Vec<u8>)) -> Self {
        Self {
            cmd: cmd_enum.into(),
            len,
            value: value,
        }
    }
}

impl From<(Cmd, Vec<u8>)> for TypeLengthValue {
    fn from((cmd_enum, value): (Cmd, Vec<u8>)) -> Self {
        Self {
            cmd: cmd_enum.into(),
            len: value.len() as u16,
            value: value,
        }
    }
}

impl From<[u8; 2]> for TypeLengthValue {
    fn from(cmd_enum: [u8; 2]) -> Self {
        Self {
            cmd: cmd_enum,
            ..Self::default()
        }
    }
}

impl From<([u8; 2], u16, Vec<u8>)> for TypeLengthValue {
    fn from((cmd_enum, len, value): ([u8; 2], u16, Vec<u8>)) -> Self {
        Self {
            cmd: cmd_enum,
            len,
            value: value,
        }
    }
}

impl TryInto<String> for TypeLengthValue {
    fn try_into(self) -> Result<String, Self::Error> {
        String::from_utf8(self.value.clone())
    }

    type Error = FromUtf8Error;
}

impl TryInto<Ipv4Addr> for TypeLengthValue {
    type Error = TLVReadingError;

    fn try_into(self) -> Result<Ipv4Addr, Self::Error> {
        if self.len == 4 {
            return Ok(Ipv4Addr::new(
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ));
        }
        Err(TLVReadingError::InvalidType(String::from(
            "Invalid type for IPv4 address",
        )))
    }
}
