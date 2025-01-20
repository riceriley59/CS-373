// clap for CLI args and dns_lookup for host lookup
use clap::Parser;
use dns_lookup::lookup_host;

// tokio to asynchronously scan ports
use tokio::task;
use tokio::net::TcpStream;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

// other imports
use std::process::exit;
use std::net::IpAddr;

// define CLI args using clap
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "")]
    ip: String,

    #[arg(short, long, default_value = "")]
    domain: String,

    #[arg(short, long, default_value = "output.txt")]
    output_filename: String,
}

// gets and validates IP address for host that we want to scan
// ports on
async fn get_target(args: &Args) -> String {
    let target: String = if !args.ip.is_empty() && args.domain.is_empty() {
        match args.ip.parse::<IpAddr>() {
            Ok(ip) if ip.is_ipv4() => ip.to_string(),
            Ok(_) => {
                eprintln!("The provided IP address is not an IPv4 address: {}", args.ip);
                exit(1);
            }
            Err(_) => {
                eprintln!("Invalid IP address provided: {}", args.ip);
                exit(1);
            }
        }
    } else if !args.domain.is_empty() && args.ip.is_empty() {
        let domain = args.domain.clone();
        match task::spawn_blocking(move || lookup_host(&domain)).await.unwrap() {
            Ok(ips) => {
                match ips.into_iter().find(|ip| ip.is_ipv4()) {
                    Some(ipv4) => ipv4.to_string(),
                    None => {
                        eprintln!("Failed to resolve domain into IPv4 address: {}", args.domain);
                        exit(1)
                    }
                }
            }
            Err(_) => {
                eprintln!("Failed to resolve domain: {}", args.domain);
                exit(1)
            }
        }
    } else {
        eprintln!("Either an IP address (-i or --ip) or Domain Name (-d or --domain) needs to be provided");
        exit(1);
    };

    return target;
}

// This is what each thread will run to scan an individual
// port
async fn scan_port(target: String, port: u16) -> Option<u16> {
   let address = format!("{}:{}", target, port); 

    if TcpStream::connect(&address).await.is_ok() {
        Some(port)
    } else {
        None
    }
}

// This handles creating all the threads to scan each
// port and then collect the results on which ports are open
async fn scan_ports(target: String) -> Vec<u16> {
    let mut tasks = Vec::new();
    let mut open_ports = Vec::new();

    for port in 1..=65535 {
        tasks.push(tokio::spawn(scan_port(target.clone(), port)));
    }

    for task in tasks {
        if let Some(port) = task.await.unwrap() {
            println!("port {} is open", port);
            open_ports.push(port);
        }
    }

    open_ports
}

// Writes the open ports to a file
async fn write_output_file(open_ports: Vec<u16>, output_filename: &str) {
    match File::create(output_filename).await {
        Ok(mut file) => {
            for port in open_ports {
                let line = format!("Port {} is open\n", port);
                if let Err(err) = file.write_all(line.as_bytes()).await {
                    eprintln!("Failed to write to file: {}", err);
                }
            }

            println!("Results saved to {}", output_filename);
        }
        Err(err) => {
            eprintln!("Failed to create output file: {}", err);
            exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Args = Args::parse();
    let target: String = get_target(&args).await;

    println!("target: {}", target); 

    let open_ports: Vec<u16> = scan_ports(target).await;

    write_output_file(open_ports, &args.output_filename).await;
}

