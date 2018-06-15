/*!
A simple, CSV-reading OpenFlow Controller dedicated to firewall bypassing.

The controller supports exactly one switch.
It involves two threads running.
One watches a CSV file for bypass rules and one implements the OpenFlow Controller using a TCP or TLS socket.

You can use mininet as a test switch.
To spawn an instance with 4 ports you can run:

```sh
# mn --controller remote,port=6653 --topo single,4 --switch ovs,protocols=OpenFlow13
```
*/

extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate ini;
extern crate ipnetwork;
#[macro_use]
extern crate log;
extern crate notify;
extern crate rand;
extern crate simple_logger;

extern crate tls_api;
#[cfg(feature = "tls")]
extern crate tls_api_openssl;

#[cfg(unix)]
extern crate libc;
#[cfg(unix)]
extern crate log_panics;
#[cfg(unix)]
extern crate syslog;

// These do not have to be public, but are to
// automatically check and generate documentation
pub mod bypass_csv;
pub mod conf;
pub mod openflow;

use bypass_csv::CsvParser;

use openflow::OfController;

use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::net;
use std::process::exit;
use std::sync::mpsc;
use std::thread;

/// Reads command line arguments and sets the program up as intended.
/// Spawns a new thread to watch the bypass file.
/// Finally runs an `OfController` infinitely.
fn handle_cli_args() -> io::Result<()> {
    #[cfg(unix)]
    let unix_opts = "
        -s, --syslog      'Logs via syslog'
        -p, --pid [file]  'Daemonizes the process and writes a PID file'";
    #[cfg(not(unix))]
    let unix_opts = "";

    let usage = &format!(
        "-v...            'Repeat to set the level of verbosity'
        -c, --conf <ini>  'The INI configuration file'
        <csv>             'The CSV file with firewall bypass rules'{}",
        unix_opts
    );
    let matches = app_from_crate!().args_from_usage(usage).get_matches();

    let log_lvl = match matches.occurrences_of("v") {
        0 => log::Level::Error,
        1 => log::Level::Warn,
        2 => log::Level::Info,
        3 => log::Level::Debug,
        _ => log::Level::Trace,
    };

    if matches.is_present("syslog") {
        let app_name = Some(crate_name!());
        let filter = log_lvl.to_level_filter();
        #[cfg(unix)]
        syslog::init(syslog::Facility::LOG_USER, filter, app_name)
            .expect("error on logging initialization");
        #[cfg(unix)]
        log_panics::init();
    }
    else {
        simple_logger::init_with_level(log_lvl).expect("error on logging initialization");
    }

    let csv_path = matches.value_of("csv").unwrap().to_string();
    let conf_path = matches.value_of("conf").unwrap();

    let (conn, table, ports, inside_net) = conf::parse_file(conf_path)?;
    let csv_parser = CsvParser::new(csv_path, inside_net);

    // first file read that terminates the program on errors
    let records = RefCell::new(csv_parser.parse_file()?);

    #[cfg(unix)]
    {
        if matches.is_present("pid") {
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(io::Error::last_os_error());
            }
            else if pid > 0 {
                let pid_path = matches.value_of("pid").unwrap();
                let mut file = File::create(pid_path)?;
                write!(file, "{}", pid)?;
                // exit the parent process
                exit(0);
            }
        }
    }

    let listen_socket = net::TcpListener::bind(conn.socket())?;
    info!("Listening on {}", listen_socket.local_addr()?);

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || csv_parser.watch_file(&tx));

    loop {
        if let Err(e) = OfController::run(&rx, &listen_socket, &conn, &table, &ports, &records) {
            error!("retry connection on error: {}", e);
        }
    }
}

/// Entry function with top level error handling.
fn main() {
    if let Err(e) = handle_cli_args() {
        error!("{}", e);
        exit(1);
    }
}
