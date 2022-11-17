use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, InetResponseHeader, SocketId, StateFlags},
    NetlinkHeader, NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

use std::collections::HashMap;
use std::io::Result;
use std::thread::sleep;
use std::time::Duration;

/// Defines the Watch internal state
/// and functionality
#[derive(Debug)]
pub struct SockWatch {
    scan_freq_ms: Duration,
    socket: Socket,
    socksmap: HashMap<u32, InetResponseHeader>,
}

impl SockWatch {
    /// Create instance of sockwatch
    /// takes scan frequency as input parameter
    pub fn new(freq: u64) -> Result<Self> {
        let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
        let _port_number = socket.bind_auto().unwrap().port_number();
        socket.connect(&SocketAddr::new(0, 0)).unwrap();

        let socksmap = HashMap::new();
        let scan_freq_ms = Duration::from_millis(freq);

        Ok(Self {
            scan_freq_ms,
            socket,
            socksmap,
        })
    }

    /// Scan sockets for their current state
    /// returns an hashmap representing the full state
    pub fn scan_sockets(&mut self) -> Result<HashMap<u32, InetResponseHeader>> {
        let mut packet = NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_DUMP,
                ..Default::default()
            },
            payload: SockDiagMessage::InetRequest(InetRequest {
                family: AF_INET,
                protocol: IPPROTO_TCP,
                extensions: ExtensionFlags::empty(),
                states: StateFlags::all(),
                socket_id: SocketId::new_v4(),
            })
            .into(),
        };

        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];
        let mut newstate = HashMap::new();

        // Before calling serialize, it is important to check that the buffer in which
        // we're emitting is big enough for the packet, other `serialize()` panics.
        assert_eq!(buf.len(), packet.buffer_len());

        packet.serialize(&mut buf[..]);

        //    println!(">>> {:?}", packet);
        if let Err(e) = self.socket.send(&buf[..], 0) {
            println!("SEND ERROR {}", e);
            return Err(e);
        }

        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;
        while let Ok(size) = self.socket.recv(&mut &mut receive_buffer[..], 0) {
            loop {
                let bytes = &receive_buffer[offset..];
                let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
                //            println!("<<< {:?}", rx_packet);

                match rx_packet.payload {
                    NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                    NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                        newstate.insert(response.header.inode, response.header);
                    }
                    NetlinkPayload::Done => {
                        return Ok(newstate);
                    }
                    _ => return Ok(newstate),
                }

                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
        }

        Ok(newstate)
    }

    /// differ creates a vector of diffs for the new scanned states
    /// it checks if new sockets are created or if the existing ones changed
    /// in state
    pub fn differ(&mut self, newmap: HashMap<u32, InetResponseHeader>) -> Result<Vec<DiffEntry>> {
        let oldmap = self.socksmap.clone();
        let mut difftable = Vec::new();
        // range new map finding added / changed sockets
        for (newinode, newhead) in &newmap {
            // if socket was previously recorded
            if oldmap.contains_key(newinode) {
                let oldstate = oldmap.get(&newinode).unwrap().state;
                let newstate = newhead.state;
                if oldstate != newstate {
                    difftable.push(DiffEntry {
                        inode: *newinode,
                        reason: String::from(&format!(
                            "state change {} -> {}",
                            self.get_state_string(oldstate),
                            self.get_state_string(newstate)
                        )),
                        payload: newhead.clone(),
                    });
                }
            // never seen this socket, add to state
            } else {
                difftable.push(DiffEntry {
                    inode: *newinode,
                    reason: String::from(&format!("new socket")),
                    payload: newhead.clone(),
                });
            }
        }

        // range old map to find removed sockets
        for (oldinode, oldhead) in oldmap {
            if !newmap.contains_key(&oldinode) {
                difftable.push(DiffEntry {
                    inode: oldinode,
                    reason: String::from(&format!("removed socket")),
                    payload: oldhead.clone(),
                });
            }
        }

        return Ok(difftable);
    }

    /// watch the full sockets state:
    /// refresh state hasmap and detect
    /// changes in socket statuses
    pub fn watch(&mut self) {
        // initialize state
        self.socksmap = self.scan_sockets().unwrap();

        println!("observing host sockets for changes");

        // loop forever
        loop {
            let newstate = self.scan_sockets().unwrap();
            let diffs = self.differ(newstate.clone()).unwrap();
            for entry in diffs {
                entry.print();
            }
            self.socksmap = newstate;
            sleep(self.scan_freq_ms);
        }
    }

    /// resolve state encoding to string value
    pub fn get_state_string(&self, state: u8) -> String {
        match state {
            1 => String::from("TCP_ESTABLISHED"),
            2 => String::from("TCP_SYN_SENT"),
            3 => String::from("TCP_SYN_RECV"),
            4 => String::from("TCP_FIN_WAIT1"),
            5 => String::from("TCP_FIN_WAIT2"),
            6 => String::from("TCP_TIME_WAIT"),
            7 => String::from("TCP_CLOSE"),
            8 => String::from("TCP_CLOSE_WAIT"),
            9 => String::from("TCP_LAST_ACK"),
            10 => String::from("TCP_LISTEN"),
            11 => String::from("TCP_CLOSING"),
            _ => String::from(""),
        }
    }
}

/// Defines a change in the sockets
/// state, new socket, removed socket,
/// change of socket state
#[derive(Debug)]
pub struct DiffEntry {
    inode: u32,
    reason: String,
    payload: InetResponseHeader,
}

impl DiffEntry {
    /// prints entry to stdout
    pub fn print(&self) {
        let mut entry = String::from("");
        entry.push_str(&format!(
            "inode: {}, reason: {}, uid: {}, src: {}:{}, dst: {}:{}",
            self.inode,
            self.reason,
            self.payload.uid,
            self.payload.socket_id.source_address,
            self.payload.socket_id.source_port,
            self.payload.socket_id.destination_address,
            self.payload.socket_id.destination_port,
        ));

        println!("{}", entry);
    }
}
