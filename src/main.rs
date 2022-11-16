// SPDX-License-Identifier: MIT

use crate::watch::SockWatch;

mod watch;

fn main() {
    let mut sw = SockWatch::new(500).unwrap();
    sw.watch();
}
