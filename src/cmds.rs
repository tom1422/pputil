use std::{net::Ipv4Addr, string::FromUtf8Error};

pub enum Cmd {
    QueryRequest,
    TransmitRequest,
    QueryResponse,
    TransmitResponse,

    CMD_Model,
    CMD_Name,
    CMD_Location,
    CMD_IPv4,

    CMD_Unknown,

    CMD_Password,

    NDSP,
    Reserved,
    EndOfMessage,

    MACBroadcast,
    MACMyPC,
}

impl Cmd {
    pub fn value(&self) -> &[u8] {
        match self {
            Cmd::QueryRequest => &[0x01, 0x01],
            Cmd::TransmitRequest => &[0x01, 0x03],
            Cmd::QueryResponse => &[0x01, 0x02],
            Cmd::TransmitResponse => &[0x10, 0x04],

            Cmd::CMD_Model => &[0x00, 0x01],
            Cmd::CMD_Name => &[0x00, 0x03],
            Cmd::CMD_Location => &[0x00, 0x05],
            Cmd::CMD_IPv4 => &[0x00, 0x06],

            Cmd::CMD_Unknown => &[0x00, 0x14],

            Cmd::CMD_Password => &[0x00, 0x0a],

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
