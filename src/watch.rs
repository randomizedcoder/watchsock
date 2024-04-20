//use anyhow::Ok;
use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, InetResponseHeader, SocketId, StateFlags},
    NetlinkHeader, NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

use std::collections::HashMap;
use std::io::Result;
use std::os::unix::io::AsRawFd;
use std::result::Result::Ok;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;

use io_uring::{
    cqueue::CompletionQueue,
    opcode,
    squeue::{self, Entry, SubmissionQueue},
    types, IoUring,
};
// use io_uring::opcode;
// use io_uring::types;
// use io_uring::IoUring;
// use io_uring::squeue::{SubmissionQueue};
// https://github.com/cloudflare/cloudflare-blog/blob/master/2022-02-io_uring-worker-pool/src/bin/udp_read.rs

use anyhow::anyhow; //, Result};
use std::io::ErrorKind;

use libc;

const SUBMIT_QUEUE_SIZE: u32 = 128;
const READ_BUFFER_SIZE: usize = 32000;
const SMALL_SLEEP_MILLISECONDS: u64 = 1;

/// Defines the Watch internal state
/// and functionality
#[derive(Debug)]
pub struct SockWatch {
    scan_freq_ms: Duration,
    socket: Socket,
    socket_fd: types::Fd,
    socksmap: HashMap<u32, InetResponseHeader>,
}

impl SockWatch {
    /// Create instance of sockwatch
    /// takes scan frequency as input parameter
    pub fn new(freq: u64) -> Result<Self> {
        let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
        let _port_number = socket.bind_auto().unwrap().port_number();
        socket.connect(&SocketAddr::new(0, 0)).unwrap();

        // https://github.com/cloudflare/cloudflare-blog/blob/master/2022-02-io_uring-worker-pool/src/bin/udp_read.rs
        let socket_fd = types::Fd(socket.as_raw_fd());

        let socksmap = HashMap::new();
        let scan_freq_ms = Duration::from_millis(freq);

        Ok(Self {
            scan_freq_ms,
            socket,
            socket_fd,
            socksmap,
        })
    }

    /// Scan sockets for their current state
    /// returns an hashmap representing the full state
    pub fn scan_sockets(&mut self) -> Result<HashMap<u32, InetResponseHeader>> {
        let mut nl_sequence = 0;

        let mut packet = NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_DUMP,
                sequence_number: nl_sequence,
                ..Default::default()
            },
            payload: SockDiagMessage::InetRequest(InetRequest {
                family: AF_INET,
                protocol: IPPROTO_TCP,
                extensions: ExtensionFlags::all(),
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
        let buffer = &buf[..];

        println!(">>> {:?}", packet);
        // Traditional syscall send
        // if let Err(e) = .send(&buf[..], 0) {
        //     println!("SEND ERROR {}", e);
        //     return Err(e);
        // }

        let mut sequence = 0;

        // https://docs.rs/io-uring/latest/io_uring/opcode/struct.Send.html
        // "The only difference between send() and write(2) is the presence of flags."
        // Source: https://www.man7.org/linux/man-pages/man2/send.2.html
        // Could use https://docs.rs/io-uring/latest/io_uring/opcode/struct.Write.html#method.new
        let send_op = opcode::Send::new(self.socket_fd, buffer.as_ptr(), buf.len() as _);
        let flags = squeue::Flags::ASYNC;
        let send_sqe = send_op.build().flags(flags).user_data(sequence);
        //let send_sqe = send_op.build().flags(flags);

        // (0) Create io_uring
        // https://docs.rs/io-uring/latest/io_uring/struct.IoUring.html#method.new
        let mut ring = IoUring::new(SUBMIT_QUEUE_SIZE)?;

        ring.submission().sync(); // load sq->head
        unsafe {
            ring.submission().push(&send_sqe);
            //let Ok(size, PushErr) = ring.submission().push(&send_sqe);
        }
        ring.submission().sync(); // store sq->tail

        // Send the NetLink Request
        // (2) Wait for at least 1 request to complete
        'restart: loop {
            match ring.submit_and_wait(1) {
                Err(e) if e.kind() == ErrorKind::Interrupted => continue 'restart,
                //Err(e) => return Err(anyhow!(e)),
                Err(e) => panic!("ring.submit_and_wait unknown error:{:?}", e),
                Ok(_) => {
                    println!("syscall complete");
                    break;
                }
            }
        }

        //let mut receive_buffer: [u8; READ_BUFFER_SIZE];
        let mut receive_buffer = vec![0; READ_BUFFER_SIZE];
        let mut offset = 0;

        ring.completion().sync(); // load cq->tail

        let mut done = false;

        while !done {
            // https://docs.rs/io-uring/latest/io_uring/opcode/struct.Recv.html
            // https://man7.org/linux/man-pages/man2/recv.2.html
            // Could use https://docs.rs/io-uring/latest/io_uring/opcode/struct.Read.html#method.new
            let recv_op = opcode::Recv::new(
                self.socket_fd,
                receive_buffer.as_mut_ptr(),
                receive_buffer.len() as _,
            );

            sequence += 1;
            println!("while recv_op, sequence:{:?}", sequence);
            let recv_sqe = recv_op.build().flags(flags).user_data(sequence);

            loop {
                ring.submission().sync(); // load sq->head
                if !ring.submission().is_full() {
                    unsafe {
                        match ring.submission().push(&recv_sqe) {
                            //let Ok(size, PushErr) = ring.submission().push(&send_sqe);
                            Err(e) => panic!("push unknown error:{:?}", e),
                            Ok(_) => {
                                println!("push complete");
                            }
                        }
                    }
                    ring.submission().sync(); // store sq->tail
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(SMALL_SLEEP_MILLISECONDS));
            }

            for cqe in ring.completion().into_iter() {
                let size = cqe.result();
                println!("recv size:{:?}", size);

                let user_data = cqe.user_data();
                assert_eq!(user_data, sequence);
                println!("user_data:{:?}", user_data);

                let bytes = &receive_buffer[offset..];
                let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
                println!("<<< {:?}", rx_packet);
                //println!("<<< {:?}", rx_packet.payload);

                match rx_packet.payload {
                    NetlinkPayload::Noop => {}
                    NetlinkPayload::Error(_) => {
                        println!("rx_packet.payload Error!");
                        //return Ok(newstate);
                    }
                    NetlinkPayload::Done => {
                        println!("rx_packet.payload Done!");
                        done = true;
                        //return Ok(newstate);
                    }
                    NetlinkPayload::Overrun(_) => {
                        return Ok(newstate);
                    }
                    NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                        newstate.insert(response.header.inode, response.header);
                    }
                    _ => return Ok(newstate),
                }

                offset += rx_packet.header.length as usize;
                if offset == size as usize || rx_packet.header.length == 0 {
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
                            "{}->{}",
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
                    reason: String::from(&format!("added")),
                    payload: newhead.clone(),
                });
            }
        }

        // range old map to find removed sockets
        for (oldinode, oldhead) in oldmap {
            if !newmap.contains_key(&oldinode) {
                difftable.push(DiffEntry {
                    inode: oldinode,
                    reason: String::from(&format!("removed")),
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
            "{:<15} {:<15} {:<25} {:<25} {:<15}",
            &format!("inode: {}", self.inode),
            &format!("uid: {}", self.payload.uid),
            &format!(
                "src: {}:{}",
                self.payload.socket_id.source_address, self.payload.socket_id.source_port
            ),
            &format!(
                "dst: {}:{}",
                self.payload.socket_id.destination_address, self.payload.socket_id.destination_port
            ),
            &format!("reason: {}", self.reason),
        ));

        println!("{}", entry);
    }
}
