use clap::Parser;
use dotenv::dotenv;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::num::ParseIntError;

use std::time::Duration;

use crate::cmds::{Cmd, TypeLengthValue};
use crate::request::Session;
use crate::response::Response;

mod actions;
mod cmds;
mod request;
mod response;

#[derive(Debug)]
pub struct Switch {
    name: String,
    model: String,
    location: String,
    ipv4_address_reported: Ipv4Addr,

    ipv4_address: String,
    mac_address: [u8; 6],
}

fn main() {
    dotenv().ok();

    println!("Prosafe plus utility / Netgear Switch Discovery Protocol (NSDP) ");

    let socket = UdpSocket::bind("0.0.0.0:63321").unwrap();

    socket
        .set_broadcast(true)
        .expect("set_broadcast call failed");
    let read_timeout_ms = 500;
    socket
        .set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))
        .unwrap();

    while user_input_loop(&socket) {}

    lifetime_test();
}

fn user_input_loop(socket: &UdpSocket) -> bool {
    let mut switches: Vec<Switch> = Vec::new();

    println!("Please choose from the following options:");
    println!("0: Exit");
    println!("1: Discover switches");
    println!("2: Perform action on discovered switch");
    println!("3: Test feature");
    print!("Enter option: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    let option: i32 = input.trim().parse().expect("Invalid integer");

    match option {
        0 => return false,
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

                if let Ok((number_of_bytes, src_addr)) = socket.recv_from(&mut buf) {
                    if let Ok(response) = Response::build(&mut buf[..number_of_bytes]) {
                        switches.push(Switch {
                            name: response.get_cmd(Cmd::CMD_Name).unwrap().try_into().unwrap(),
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
                }
            }

            println!("Final switches array: {:?}", switches);
        }
        2 => {
            println!("Using switch loaded in ENV file!");

            let switch = load_switch_from_dotenv();

            let login_tlv = TypeLengthValue::from((Cmd::CMD_Password, 8, password()));

            perform_action(&socket, switch, login_tlv);
        }
        3 => {
            println!("Debug test message");
            password_test();
        }
        _ => {
            println!("Invalid option selected!");
        }
    }
    true
}

fn perform_action(socket: &UdpSocket, switch: Switch, login_tlv: TypeLengthValue) {
    let action = actions::ActionRunner::new(socket, &switch);

    action.get_all_info(&login_tlv);
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

fn load_switch_from_dotenv() -> Switch {
    let name = std::env::var("TESTSWITCH_NAME").expect("TESTSWITCH_NAME not set");
    let model = std::env::var("TESTSWITCH_MODEL").expect("TESTSWITCH_MODEL not set");
    let location = std::env::var("TESTSWITCH_LOCATION").expect("TESTSWITCH_LOCATION not set");
    let ipv4_address_reported: Ipv4Addr = Ipv4Addr::from(
        <Vec<u8> as TryInto<[u8; 4]>>::try_into(csv_to_byte_array(
            std::env::var("TESTSWITCH_IPV4_REPORTED")
                .expect("TESTSWITCH_IPV4_REPORTED not set")
                .as_str(),
        ))
        .unwrap(),
    );
    let ipv4_address = std::env::var("TESTSWITCH_IPV4").expect("TESTSWITCH_IPV4 not set");
    let mac_address: [u8; 6] = csv_to_byte_array(
        std::env::var("TESTSWITCH_MAC")
            .expect("TESTSWITCH_MAC not set")
            .as_str(),
    )
    .try_into()
    .unwrap();

    Switch {
        name,
        model,
        location,
        ipv4_address_reported,
        ipv4_address,
        mac_address,
    }
}

fn csv_to_byte_array(str: &str) -> Vec<u8> {
    let comma_ascii: char = char::from_u32(",".as_bytes()[0] as u32).unwrap();
    let mut bytes: Vec<u8> = Vec::new();
    let mut start = 0;
    let mut end = 0;
    for char in str.chars() {
        if char == comma_ascii {
            let num: u8 = str[start..end].parse().unwrap();
            bytes.push(num);
            start = end + 1;
        }
        end += 1;
    }
    let num: u8 = str[start..end].parse().unwrap();
    bytes.push(num);
    bytes.try_into().unwrap()
}

fn lifetime_test() {
    let str1 = String::from("Longer string");
    let str2 = String::from("Short");
    let longer;
    {
        longer = test_2(&str1, &str2);
    }

    println!("Invalid! {}", longer);
}

fn test_2<'a>(st: &'a str, sl: &'a str) -> &'a str {
    if st.len() > sl.len() {
        st
    } else {
        sl
    }
}
