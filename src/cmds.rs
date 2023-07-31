use std::{net::Ipv4Addr, string::FromUtf8Error};

pub enum Cmd {
    QueryRequest,
    TransmitRequest,
    QueryResponse,
    TransmitResponse,

    CMD_Model,
    CMD_Name,
    CMD_Switch_MAC,
    CMD_Location,
    CMD_IPv4,
    CMD_Switch_Netmask,

    

    CMD_Password,

    NDSP,
    Reserved,
    EndOfMessage,

    MACBroadcast,
    MACMyPC,
    CMD_Switch_Gateway,
    CMD_Switch_DHCP,
    CMD_FW_Version,
    CMD_FW_Version_2,
    CMD_FW_Active,
    CMD_Port_Count,
    CMD_0002,
    CMD_000C,
    CMD_0014,
    CMD_7C00,
    CMD_7400,
    CMD_0C00,
    CMD_7800,
    CMD_1000,
    CMD_5C00,
    CMD_2000,
    CMD_6800,
    CMD_6C00,
    CMD_7000,
    CMD_9000,
    CMD_6400,
    CMD_3400,
    CMD_5000,
    CMD_4C00,
    CMD_5400,
}

impl Cmd {
    pub fn value(&self) -> &[u8] {
        match self {
            Cmd::QueryRequest => &[0x01, 0x01],
            Cmd::TransmitRequest => &[0x01, 0x03],
            Cmd::QueryResponse => &[0x01, 0x02],
            Cmd::TransmitResponse => &[0x10, 0x04],

            Cmd::CMD_Model => &[0x00, 0x01],
            Cmd::CMD_0002 => &[0x00, 0x02],
            Cmd::CMD_Name => &[0x00, 0x03],
            Cmd::CMD_Switch_MAC => &[0x00, 0x04],
            Cmd::CMD_Location => &[0x00, 0x05],
            Cmd::CMD_IPv4 => &[0x00, 0x06],
            Cmd::CMD_Switch_Netmask => &[0x00, 0x07],
            Cmd::CMD_Switch_Gateway => &[0x00, 0x08],
            Cmd::CMD_Password => &[0x00, 0x0a],
            Cmd::CMD_Switch_DHCP => &[0x00, 0x0b],
            Cmd::CMD_000C => &[0x00, 0x0c],
            Cmd::CMD_FW_Version => &[0x00, 0x0d],
            Cmd::CMD_FW_Version_2 => &[0x00, 0x0e],
            Cmd::CMD_FW_Active => &[0x00, 0x0f],

            Cmd::CMD_0014 => &[0x00, 0x14],             //Usually 4 bytes like 00 00 00 01 

            Cmd::CMD_0C00 => &[0x0C, 0x00],             //Response: n copies of 3 byte TLVs where n is port count
            Cmd::CMD_1000 => &[0x10, 0x00],             //Response: n copies of 49 byte TLVs where n is port count

            Cmd::CMD_2000 => &[0x20, 0x00],             //Usually 1 byte like 00

            Cmd::CMD_3400 => &[0x34, 0x00],             //Usually 1 byte like 02

            Cmd::CMD_4C00 => &[0x4c, 0x00],             //Response: n copies of 5 byte TLVs where n is port count

            Cmd::CMD_5000 => &[0x50, 0x00],             //Response: n copies of 5 byte TLVs where n is port count
            Cmd::CMD_5400 => &[0x54, 0x00],             //Usually 1 byte like 00
            Cmd::CMD_5C00 => &[0x5c, 0x00],             //Usually 3 bytes like 00 00 00

            Cmd::CMD_Port_Count => &[0x60, 0x00],

            Cmd::CMD_6400 => &[0x64, 0x00],             //Usually 2 bytes like 00 20
            Cmd::CMD_6800 => &[0x68, 0x00],             //Usually 4 bytes like 00 01 00 01
            Cmd::CMD_6C00 => &[0x6C, 0x00],             //Usually 1 byte like 00

            Cmd::CMD_7000 => &[0x70, 0x00],             //Usually 1 byte like 00
            Cmd::CMD_7400 => &[0x74, 0x00],             //Usually 8 bytes like 00 00 00 08 7f fc ff ff
            Cmd::CMD_7800 => &[0x78, 0x00],             //Usually 21 bytes like 01 30 30 31 31 31 31 31 31 31 31 31 31 31 00 00 1 20 10 00 a2
            Cmd::CMD_7C00 => &[0x7c, 0x00],             //Usually 1 byte like 01

            Cmd::CMD_9000 => &[0x90, 0x00],             //Usually 1 byte like 00

            Cmd::NDSP => &[0x4E, 0x53, 0x44, 0x50],
            Cmd::Reserved => &[0x00, 0x00],
            Cmd::EndOfMessage => &[0xFF, 0xFF, 0x00, 0x00],

            Cmd::MACBroadcast => &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            Cmd::MACMyPC => &[0x4c, 0xcc, 0x6a, 0x6c, 0xce, 0x7e],
        }
    }
}


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
            cmd: cmd_enum.value().try_into().unwrap(),
            ..Self::default()
        }
    }
}

impl From<(Cmd, u16, Vec<u8>)> for TypeLengthValue {
    fn from((cmd_enum, len, value): (Cmd, u16, Vec<u8>)) -> Self {
        Self {
            cmd: cmd_enum.value().try_into().unwrap(),
            len,
            value: value,
        }
    }
}

impl From<(Cmd, Vec<u8>)> for TypeLengthValue {
    fn from((cmd_enum, value): (Cmd, Vec<u8>)) -> Self {
        Self {
            cmd: cmd_enum.value().try_into().unwrap(),
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

impl TypeLengthValue {
    pub fn from_raw(raw: &[u8]) -> Result<(TypeLengthValue, usize), TLVReadingError> {
        if raw.len() < 4 {
            return Err(TLVReadingError::ArrTooShort(String::from(
                "Raw array too short for type/length",
            )));
        }

        if &raw[0..4] == Cmd::EndOfMessage.value() {
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
        if self.cmd == cmd.value() {
            return true;
        }
        false
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
