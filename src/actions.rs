use std::net::{UdpSocket, SocketAddr};

use crate::{
    cmds::{self, TypeLengthValue, Cmd},
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

        let request = request::Request::builder()
            .ctype(cmds::Cmd::QueryRequest.value().try_into().unwrap())
            .session(Session::new_random_seq(
                cmds::Cmd::MACMyPC.value().try_into().unwrap(),
                self.switch.mac_address,
            ))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_Model))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_0002))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_Name))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_Switch_MAC))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_Location))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_IPv4))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_Switch_Netmask))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_Switch_Gateway))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_Switch_DHCP))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_000C))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_FW_Version))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_FW_Version_2))
            .add_cmd(TypeLengthValue::from(Cmd::CMD_FW_Active))
            .build();

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
            .ctype(cmds::Cmd::TransmitRequest.value().try_into().unwrap())
            .session(Session::new_random_seq(
                cmds::Cmd::MACMyPC.value().try_into().unwrap(),
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
