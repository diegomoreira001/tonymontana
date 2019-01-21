use std::mem;
use std::net;
use pnet::datalink;
use pnet::transport;

fn main() {

    //Simple light-weight packet sniffer
    //We'll trust in libpnet. Should be cross-platform.
    //Only TCP for now

    //1. Check args and show usage. Something like -> USAGE: tony --sniff eth0

    //2. Retrieve interface from args, search for it at OS level, and allocate it.

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
