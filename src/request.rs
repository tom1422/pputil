use std::borrow::BorrowMut;

use crate::cmds::TypeLengthValue;

#[derive(Debug, PartialEq)]
pub struct Session {
    seq: [u8; 2],
    source_mac: [u8; 6],
    dest_mac: [u8; 6],
}

impl Session {
    pub fn new(source_mac: [u8; 6], dest_mac: [u8; 6], seq: [u8; 2]) -> Session {
        Session {
            seq,
            source_mac,
            dest_mac,
        }
    }

    pub fn new_random_seq(source_mac: [u8; 6], dest_mac: [u8; 6]) -> Session {
        Session {
            seq: [0x00, rand::random::<u8>()],
            source_mac,
            dest_mac,
        }
    }

    pub fn get_switch_mac(&self) -> [u8; 6] {
        self.dest_mac
    }
}

#[derive(Debug, PartialEq)]
pub struct Request {
    cmds: Vec<TypeLengthValue>,
    ctype: [u8; 2],

    session: Session, //Persistent details

    nsdp: [u8; 4],       //Constants
    reserved: [u8; 2],   //   |
    end_of_msg: [u8; 4], //   _
}

impl Request {
    pub fn builder() -> RequestBuilder {
        RequestBuilder::new()
    }

    pub fn format(&self) -> Vec<u8> {
        let mut head: [u8; 32] = [0; 32];
        head[0..2].copy_from_slice(&self.ctype);
        //head[2..8] reserved so already all 0s
        head[8..14].copy_from_slice(&self.session.source_mac);
        head[14..20].copy_from_slice(&self.session.dest_mac);
        //head[20..22] reserved so already all 0s
        head[22..24].copy_from_slice(&self.session.seq);
        head[24..28].copy_from_slice(&self.nsdp);
        //head[28..32] also reserved

        let mut vec: Vec<u8> = Vec::new();

        vec.append(&mut head.to_vec());

        for cmd in self.cmds.iter() {
            vec.append(&mut cmd.to_raw());
        }

        vec.append(&mut Vec::from(self.end_of_msg));

        vec
    }
}

#[derive(Default)]
pub struct RequestBuilder {
    cmds: Vec<TypeLengthValue>,
    session: Option<Session>,
    ctype: Option<[u8; 2]>,
}

impl RequestBuilder {
    pub fn new() -> RequestBuilder {
        RequestBuilder {
            cmds: Vec::new(),
            session: None,
            ctype: None,
        }
    }

    pub fn ctype(mut self, value: [u8; 2]) -> RequestBuilder {
        self.ctype = Some(value);
        self
    }

    pub fn add_cmd(mut self, cmd: TypeLengthValue) -> RequestBuilder {
        self.cmds.push(cmd);
        self
    }

    pub fn session(mut self, value: Session) -> RequestBuilder {
        self.session = Some(value);
        self
    }

    pub fn build(mut self) -> Request {
        Request {
            cmds: self.cmds,
            ctype: self.ctype.expect("CType must be provided!"),
            session: self.session.expect("Session information must be provided!"),
            nsdp: crate::cmds::ProtoConsts::NDSP.value()[0..4].try_into().unwrap(),
            reserved: crate::cmds::ProtoConsts::Reserved.value()[0..2].try_into().unwrap(),
            end_of_msg: crate::cmds::ProtoConsts::EndOfMessage.value()[0..4]
                .try_into()
                .unwrap(),
        }
    }
}
