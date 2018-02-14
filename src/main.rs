/*!
A simple, CSV-reading OpenFlow controller dedicated to firewall bypassing.

The controller supports exactly one switch.
You can use mininet as a test switch.
To spawn an instance with 4 ports you can run:

```sh
# mn --controller remote,port=6653 --topo single,4 --switch ovs,protocols=OpenFlow13
```
*/

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate log_panics;
extern crate simple_logger;
extern crate byteorder;
extern crate ini;
extern crate notify;
extern crate ipnetwork;
extern crate rand;

extern crate tls_api;
#[cfg(feature = "tls")]
extern crate tls_api_openssl;

#[cfg(unix)]
extern crate syslog;
#[cfg(unix)]
extern crate libc;

mod bypass_csv;
mod openflow;
mod conf;

use bypass_csv::BypassRecord;
use bypass_csv::CsvParser;

use notify::{Watcher, RecursiveMode, DebouncedEvent};

use openflow::OfController;

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::net;
use std::process::exit;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use std::thread;
use std::time::Duration;

const NOTIFY_SECONDS: u64 = 2;

/// Registers a file as notify target.
/// If the registering fails, the file is tried to be reregistered infinitely.
fn register_bypass_file(parser: &CsvParser, record_tx: &Sender<HashSet<BypassRecord>>) {
    loop {
        let (tx, rx) = mpsc::channel();
        if let Ok(mut watcher) = notify::watcher(tx, Duration::from_secs(NOTIFY_SECONDS)) {
            if watcher.watch(&parser.path, RecursiveMode::NonRecursive).is_ok() {
                info!("Watching file {}", parser.path);
                match handle_file_events(&rx, parser, record_tx) {
                    Ok(_) => warn!("notify watch removed"),
                    Err(e) => error!("{}", e),
                }
            }
        }
    }
}

/// Reads inode events and parses the corresponding file.
/// If the inode is (re)moved, it is unregistered from notify.
/// On unregistering, which can also be caused by deleting,
/// unmounting etc., the causing event's mask is returned.
fn handle_file_events(
    rx: &Receiver<DebouncedEvent>,
    parser: &CsvParser,
    tx: &Sender<HashSet<BypassRecord>>,
) -> notify::Result<()> {
    loop {
        match rx.recv().expect("inter-thread communication failed") {
            DebouncedEvent::NoticeRemove(_) | DebouncedEvent::Remove(_) => {
                return Ok(());
            }
            DebouncedEvent::Error(error, _) => {
                return Err(error);
            }
            _ => {
                match parser.parse_file() {
                    Ok(recs) => tx.send(recs).expect("inter-thread communication failed"),
                    Err(io_err) => {
                        return Err(notify::Error::Io(io_err));
                    }
                }
            }
        }
    }
}

/// Reads command line arguments and calls the corresponding functions.
fn handle_cli_args() -> io::Result<()> {
    #[cfg(unix)]
    let unix_opts =
        "-p, --pid [file] 'Daemonizes the process and writes a PID file'
        -s, --syslog      'Logs via syslog'
        ";
    #[cfg(not(unix))]
    let unix_opts = "";

    let usage = &format!(
        "{}-v...          'Repeat to set the level of verbosity'
        -c, --conf <ini>  'The INI configuration file.'
        <csv>             'The CSV file with firewall bypass rules'"
    , unix_opts);
    let matches = app_from_crate!().args_from_usage(usage).get_matches();

    let log_lvl = match matches.occurrences_of("v") {
        0 => log::LogLevel::Error,
        1 => log::LogLevel::Warn,
        2 => log::LogLevel::Info,
        3 => log::LogLevel::Debug,
        _ => log::LogLevel::Trace,
    };

    if matches.is_present("syslog") {
        let app_name = Some(crate_name!());
        let filter = log_lvl.to_log_level_filter();
        #[cfg(unix)]
        syslog::init(syslog::Facility::LOG_USER, filter, app_name).expect("error on logging initialization");
        log_panics::init();
    } else {
        simple_logger::init_with_level(log_lvl).expect("error on logging initialization");
    }

    let csv_path = matches.value_of("csv").expect("required csv argument").to_string();
    let conf_path = matches.value_of("conf").unwrap();

    let (conn, table, ports, inside_net) = conf::parse_file(conf_path)?;
    let csv_parser = CsvParser::new(csv_path, inside_net);

    #[cfg(unix)] {
        if matches.is_present("pid") {
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(io::Error::last_os_error());
            } else if pid > 0 {
                // exit the parent process
                exit(0);
            }
            let pid_path = matches.value_of("pid").expect("pid file path missing");
            let mut file = File::create(pid_path)?;
            write!(file, "{}", pid)?;
        }
    }

    // first file read that terminates the program on errors
    let records = RefCell::new(csv_parser.parse_file()?);

    let listen_socket = net::TcpListener::bind(conn.socket)?;
    info!("Listening on {}", listen_socket.local_addr()?);

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || register_bypass_file(&csv_parser, &tx));
    
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
