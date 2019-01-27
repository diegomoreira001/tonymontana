extern crate pnet;

use pnet::datalink::{self, NetworkInterface};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use std::env;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process;

//Simple light-weight packet sniffer
//We'll trust in libpnet. Should be cross-platform.
//Only TCP dumping for now; future stuff like actual sniffing at the bottom
// tony --dump <IFACE>
// tony --sniff --silent ...
// tony --craft

//This is meant for development purposes, integration testing, and sutff...
fn main() {


    use pnet::datalink::Channel::Ethernet;


    //1. Check args and show usage. Something like -> USAGE: tony eth0
    let first_arg = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: tony <IFACE>").unwrap();
            process::exit(1);
        }
    };

    let predicate = |net_iface: &NetworkInterface| net_iface.name == first_arg;
    //2. Retrieve interface from args, search for it at OS level, and allocate it.
    let network_interfaces = datalink::interfaces();
    let network_interface = network_interfaces.into_iter()
        .filter(predicate)
        .next()
        .unwrap();

    //3. Create a channel over the iface.
    //Boxing a DataLinkReceiver
    let (_, mut rx) = match datalink::channel(&network_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    //Loop here {
    //Taken from library examples - Need tweaking
    loop {

        //4. Create a buffer, and start sniffing.
        // Just TCP for the time being.
        // if packet ok ->
        //5. Print the packet... Format?
        // else -> print error, do not break
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        // Create a fake frame for libpnet and fill it with the packet
        match rx.next() {
            Ok(packet) => {
                if cfg!(target_os = "macos") && network_interface.is_up() && !network_interface.is_broadcast()
                    && !network_interface.is_loopback() && network_interface.is_point_to_point()
                {
                    // Maybe is TUN interface
                    let version = Ipv4Packet::new(&packet).unwrap().get_version();
                    if version == 4 {
                        fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                        fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                        fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                        fake_ethernet_frame.set_payload(&packet);
                        handle_ethernet_frame(&network_interface, &fake_ethernet_frame.to_immutable());
                        continue;
                    } else if version == 6 {
                        fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                        fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                        fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                        fake_ethernet_frame.set_payload(&packet);
                        handle_ethernet_frame(&network_interface, &fake_ethernet_frame.to_immutable());
                        continue;
                    }
                }
                handle_ethernet_frame(&network_interface, &EthernetPacket::new(packet).unwrap());
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }



    //6. Clean stuff

    //Future stuff: UDP, should be pretty straightforward

    //Sniffing on local iface and switches

    //Package interception and crafting. Mode tony --intercept --craft eth0 someArgs...
    //Mostly aimed at integration test purposes
}


fn handle_ethernet_frame(network_interface: &NetworkInterface, ethernet_packet: &EthernetPacket) {

    let interface_name = &network_interface.name[..];
    //check packet type, may be IPv4, IPv6
    //generic arp types won't panic but will be discarded, no warning either
    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let header = Ipv4Packet::new(ethernet_packet.payload());
            if let Some(header) = header {
                handle_transport_protocol(
                    interface_name,
                    IpAddr::V4(header.get_source()),
                    IpAddr::V4(header.get_destination()),
                    header.get_next_level_protocol(),
                    header.payload(),
                );
            } else {
                println!("[{}]: Malformed IPv4 Packet", interface_name);
            }
        }
        EtherTypes::Ipv6 => {
            let header = Ipv6Packet::new(ethernet_packet.payload());
            if let Some(header) = header {
                handle_transport_protocol(
                    interface_name,
                    IpAddr::V6(header.get_source()),
                    IpAddr::V6(header.get_destination()),
                    header.get_next_header(),
                    header.payload(),
                );
            } else {
                println!("[{}]: Malformed IPv6 Packet", interface_name);
            }
        }
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet_packet.get_source(),
            ethernet_packet.get_destination(),
            ethernet_packet.get_ethertype(),
            ethernet_packet.packet().len()
        ),
    }

}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
         IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet)
         }
         _ => println!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()

        ),
    }
}


//TODO: format packet
fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}; packet: {:?}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len(),
            packet
        );
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}