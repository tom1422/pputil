use std::io::{self, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::num::ParseIntError;

use std::time::Duration;

use crate::cmds::{Cmd, TypeLengthValue};
use crate::request::Session;
use crate::response::Response;

mod cmds;
mod request;
mod response;

#[derive(Debug)]
struct Switch {
    name: String,
    model: String,
    location: String,
    ipv4_address_reported: Ipv4Addr,

    ipv4_address: String,
    mac_address: [u8; 6],
}

fn main() {
    println!("Prosafe plus utility / Netgear Switch Discovery Protocol (NSDP) ");

    let socket = UdpSocket::bind("0.0.0.0:63321").unwrap();

    socket
        .set_broadcast(true)
        .expect("set_broadcast call failed");

    let read_timeout_ms = 500;
    socket
        .set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))
        .unwrap();

    let mut switches: Vec<Switch> = Vec::new();

    'user_input: loop {
        println!("Please choose from the following options:");
        println!("0: Exit");
        println!("1: Discover switches");
        println!("2: Select discovered switch");
        println!("3: Test feature");
        print!("Enter option: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
        let option: Result<i32, ParseIntError> = input.trim().parse();
        match option {
            Ok(option) => match option {
                0 => {
                    println!("exiting");
                    break 'user_input;
                }
                1 => {
                    let request = request::Request::builder()
                        .ctype(cmds::Cmd::QueryRequest.value().try_into().unwrap())
                        .session(Session::new_random_seq(
                            cmds::Cmd::MACMyPC.value().try_into().unwrap(),
                            cmds::Cmd::MACBroadcast.value().try_into().unwrap(),
                        ))
                        .add_cmd(TypeLengthValue::from(Cmd::CMD_Name))
                        .add_cmd(TypeLengthValue::from(Cmd::CMD_Model))
                        .add_cmd(TypeLengthValue::from(Cmd::CMD_Location))
                        .add_cmd(TypeLengthValue::from(Cmd::CMD_IPv4))
                        .build();

                    let buf = request.format();

                    socket
                        .send_to(buf.as_slice(), "255.255.255.255:63322")
                        .unwrap();

                    let discover_count = 6;

                    for _ in 0..discover_count {
                        let mut buf = [0; 128];
                        let muc = socket.recv_from(&mut buf);
                        match muc {
                            Ok((number_of_bytes, src_addr)) => {
                                let response = Response::build(&mut buf[..number_of_bytes]);
                                switches.push(Switch {
                                    name: response
                                        .get_cmd(Cmd::CMD_Name)
                                        .unwrap()
                                        .try_into()
                                        .unwrap(),
                                    model: response
                                        .get_cmd(Cmd::CMD_Model)
                                        .unwrap()
                                        .try_into()
                                        .unwrap(),
                                    location: response
                                        .get_cmd(Cmd::CMD_Location)
                                        .unwrap()
                                        .try_into()
                                        .unwrap(),
                                    ipv4_address_reported: response
                                        .get_cmd(Cmd::CMD_IPv4)
                                        .unwrap()
                                        .try_into()
                                        .unwrap(),

                                    ipv4_address: src_addr.to_string(),
                                    mac_address: response.get_session().get_switch_mac(),
                                });
                            }
                            Err(_) => {
                                println!("No more replies. Found {} switches", switches.len());
                                break;
                            }
                        }
                    }

                    println!("Final switches array: {:?}", switches);
                }
                2 => {
                    println!("Using thomas room switch");

                    let switch = Switch {
                        name: String::from("Thomas' Room Switch"),
                        model: String::from("GS105Ev2"),
                        location: String::from(""),
                        ipv4_address_reported: Ipv4Addr::new(192, 168, 4, 231),
                        ipv4_address: String::from("192.168.4.231:63322"),
                        mac_address: [16, 218, 67, 30, 98, 1],
                    };

                    let login_tlv: (Cmd, u16, Vec<u8>) = (Cmd::CMD_Password, 8, password());

                    let request = request::Request::builder()
                        .ctype(cmds::Cmd::TransmitRequest.value().try_into().unwrap())
                        .session(Session::new_random_seq(
                            cmds::Cmd::MACMyPC.value().try_into().unwrap(),
                            switch.mac_address,
                        ))
                        .add_cmd(TypeLengthValue::from(login_tlv))
                        .build();

                    let buf = request.format();

                    socket
                        .send_to(buf.as_slice(), "255.255.255.255:63322")
                        .unwrap();

                    let mut buf = [0; 128];
                    let resp = socket.recv_from(&mut buf);

                    match resp {
                        Ok((number_of_bytes, addr)) => {
                            let response = Response::build(&mut buf[..number_of_bytes]);
                            println!("Reponse: {:?}", response);
                        },
                        Err(_) => {println!("incorrect password or invalid address"); continue 'user_input;},
                    }
                }
                3 => {
                    println!("Debug test message");
                    password_test();
                }
                _ => {
                    println!("Invalid option selected!");
                    continue 'user_input;
                }
            },
            Err(_) => {
                println!("Failed to parse input as valid integer");
                continue 'user_input;
            }
        }
    }
}

fn password() -> Vec<u8> {
    let plainpass = "password".as_bytes();
    let hashkey = "NtgrSmartSwitchRock".as_bytes();

    let mut password: Vec<u8> = Vec::<u8>::new();

    for (plain_char, hash_char) in plainpass.iter().zip(hashkey) {
        let xor = plain_char ^ hash_char;
        password.push(xor);
    }
    password
}

fn password_test() {
    let password: Vec<u8> = password();
    print!("Password xor: ");
    print_hex(&password);
    println!();
}

fn print_hex(value: &Vec<u8>) {
    for byte in value {
        print!("{:02x} ", byte);
    }
}
