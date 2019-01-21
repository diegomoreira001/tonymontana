use std::mem;
use std::net;
use std::process;
use std::env;
use pnet::datalink::{self, NetworkInterface};

use pnet::transport;


fn main() {

    //Simple light-weight packet sniffer
    //We'll trust in libpnet. Should be cross-platform.
    //Only TCP for now

    //1. Check args and show usage. Something like -> USAGE: tony eth0
    let first_arg = env::args().nth(1);
    if first_arg.is_none() {
        eprintln!("USAGE: tony <IFACE>");
        process::exit(1);
    }

    //2. Retrieve interface from args, search for it at OS level, and allocate it.
    let network_interfaces = datalink::interfaces();
    let network_interface = network_interfaces.into_iter()
        .filter(|net_iface: &NetworkInterface| net_iface.name == first_arg)
        .next()
        .unwrap();

    //3. Create a channel over the iface.

    //Loop here {

        //4. Create a buffer, and start sniffing.
        // Just TCP for the time being.
            // if packet ok ->
        //5. Print the packet... Format?
            // else -> print error, do not break

    //} end-loop

    //6. Clean stuff

    //Future stuff: UDP, should be pretty straightforward
    //Package interception and crafting. Mode tony --intercept --craft eth0 someArgs...
    //Mostly aimed at integration test purposes
}
