use std::string::FromUtf8Error;

use crate::cmds::{Cmd, TLVReadingError, TypeLengthValue};
use crate::request::Session;

#[derive(Debug)]
pub struct Response {
    cmds: Vec<TypeLengthValue>,
    ctype: [u8; 2],
    session: Session, //Persistent details from switch. Source MAC is still PC's and Dest MAC is still Switches'
}

impl Response {
    pub fn build(msg: &[u8]) -> Response {
        let ctype: [u8; 2] = msg[0..2].try_into().unwrap();
        //2 to 8 is reserved
        let source_mac: [u8; 6] = msg[8..14].try_into().unwrap();
        let dest_mac: [u8; 6] = msg[14..20].try_into().unwrap();
        //20 to 22 is reserved
        let seq: [u8; 2] = msg[22..24].try_into().unwrap();
        let _nsdp: [u8; 4] = msg[24..28].try_into().unwrap();

        let mut cmds: Vec<TypeLengthValue> = Vec::new();

        let mut current_index: usize = 32;

        loop {
            let read_result = TypeLengthValue::from_raw(&msg[current_index..]);
            match read_result {
                Ok((tlv, len_index)) => {
                    current_index += len_index;
                    cmds.push(tlv);
                }
                Err(error) => match error {
                    TLVReadingError::ArrTooShort(message) => {
                        panic!("Error reading TLV {}", message)
                    }
                    TLVReadingError::EndOfMessage => break,
                    _ => {},
                },
            }
        }

        Response {
            cmds,
            ctype,
            session: Session::new(source_mac, dest_mac, seq),
        }
    }

    pub fn get_session(&self) -> &Session {
        &self.session
    }

    pub fn get_cmds(&self) -> &Vec<TypeLengthValue> {
        &self.cmds
    }

    pub fn get_cmd(&self, cmd: Cmd) -> Result<TypeLengthValue, String> {
        for a in &self.cmds {
            if a.cmd_equal_to(&cmd) {
                return Ok(a.clone());
            }
        }
        Err(String::from("Not found"))
    }

}
