use std::net::{UdpSocket, SocketAddr};

use crate::{
    cmds::{self, TypeLengthValue},
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


    }



    fn login(&self, password: &TypeLengthValue) -> Result<Response, std::io::Error> {
        let request = request::Request::builder()
            .ctype(cmds::Cmd::TransmitRequest.value().try_into().unwrap())
            .session(Session::new_random_seq(
                cmds::Cmd::MACMyPC.value().try_into().unwrap(),
                self.switch.mac_address,
            ))
            .add_cmd(password.clone())
            .build();

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
