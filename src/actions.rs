use std::net::{UdpSocket, SocketAddr};

use strum::IntoEnumIterator;

use crate::{
    cmds::{self, TypeLengthValue, Cmd, CmdAttributes},
    request::{self, Session},
    Switch, response::Response,
};

pub struct ActionRunner<'a> {
    socket: &'a UdpSocket,
    switch: &'a Switch,
}

impl<'a> ActionRunner<'a> {
    pub fn new(socket: &'a UdpSocket, switch: &'a Switch) -> ActionRunner<'a> {
        ActionRunner { socket, switch }
    }

    pub fn get_all_info(&self, password: &TypeLengthValue) {
        
        let resp = self.login(password);
        println!("{:?}", resp);

        //Get actual info

        let mut request_builder = request::Request::builder()
            .ctype(cmds::ProtoConsts::QueryRequest.value().try_into().unwrap())
            .session(Session::new_random_seq(
                cmds::ProtoConsts::MACMyPC.value().try_into().unwrap(),
                self.switch.mac_address,
            ));

        for cmd in Cmd::iter() {
            if cmd.is_flag_set(CmdAttributes::READ_ONLY) {
                request_builder = request_builder.add_cmd(TypeLengthValue::from(cmd));
            }
        }

        let request = request_builder.build();
            

        println!("Request: {:?}", request);

        let buf = request.format();

        

        self.socket
            .send_to(buf.as_slice(), "255.255.255.255:63322")
            .unwrap();

        let mut buf = [0; 1024];
        let (usize, _) = self.socket.recv_from(&mut buf).unwrap();

        let resp = Response::build(&buf[..usize]).unwrap();
        
        println!("Response: {:?}", resp)

    }



    fn login(&self, password: &TypeLengthValue) -> Result<Response, std::io::Error> {
        let request = request::Request::builder()
            .ctype(cmds::ProtoConsts::TransmitRequest.value().try_into().unwrap())
            .session(Session::new_random_seq(
                cmds::ProtoConsts::MACMyPC.value().try_into().unwrap(),
                self.switch.mac_address,
            ))
            .add_cmd(password.clone())
            .build();

        println!("Request: {:?}", request);

        let buf = request.format();

        

        self.socket
            .send_to(buf.as_slice(), "255.255.255.255:63322")
            .unwrap();

        let mut buf = [0; 128];
        let resp = self.socket.recv_from(&mut buf);

        match resp {
            Ok((usize, _)) => {
                return Ok(Response::build(&buf[..usize]).unwrap())
            },
            Err(kind) => {
                return Err(kind);
            },
        }
    }
}
