// clap for CLI args and dns_lookup for host lookup
use clap::Parser;
use dns_lookup::lookup_host;

// tokio to asynchronously scan ports, write to files, etc.
use tokio::task;
use tokio::net::TcpStream;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

// other imports
use std::process::exit;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

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

// holds mappings from well_known_ports to it's corresponding
// service
fn get_service_by_port(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("SSH"),
        80 => Some("HTTP"),
        443 => Some("HTTPS"),
        _ => None,
    }
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

    let timeout = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&address)); 

    match timeout.await {
        Ok(Ok(_)) => Some(port),
        _ => None,
    }
}

// This handles creating all the threads to scan each
// port and then collect the results on which ports are open
async fn scan_ports(target: String) -> Vec<u16> {
    let mut tasks = Vec::new();
    let mut open_ports = Vec::new();

    // create sempahore with 1000 available spots
    // This makes it so that only 1000 threads can
    // run at the same time
    let semaphore = Arc::new(Semaphore::new(1000));

    for port in 1..=65535 {
        // have to clone so each thread doesn't own
        // target or the semaphore
        let semaphore = Arc::clone(&semaphore);
        let target_copy = target.clone();

        tasks.push(tokio::spawn(async move {
            let permit = semaphore.acquire().await.unwrap();
            let result = scan_port(target_copy, port).await;
            drop(permit);
            result
        }));
    }

    println!("PORT  STATE  SERVICE\n");

    for task in tasks {
        if let Some(port) = task.await.unwrap() {
            let service = get_service_by_port(port).unwrap_or("<unknown>");

            println!("{}  open  {}", port, service);
            open_ports.push(port);
        }
    }

    open_ports
}

// Writes the open ports to a file
async fn write_output_file(open_ports: Vec<u16>, target: String, args: &Args) {
    match File::create(args.output_filename.clone()).await {
        Ok(mut file) => {
            let start_line = format!("Starting BadMap {}\n", option_env!("CARGO_PKG_VERSION").unwrap_or("<uknown>"));
            if let Err(err) = file.write_all(start_line.as_bytes()).await {
                eprintln!("Failed to write to file: {}", err);
            }

            let target_line: String;
            if !args.domain.is_empty() {
                target_line = format!("BadMap Scan Report for {} ({})\n\n", args.domain, target);
            } else {
                target_line = format!("BadMap Scan Report for {}\n\n", target);
            }
            if let Err(err) = file.write_all(target_line.as_bytes()).await {
                eprintln!("Failed to write to file: {}", err);
            }

            if let Err(err) = file.write_all(format!("PORT  STATE  SERVICE\n\n").as_bytes()).await {
                eprintln!("Failed to write to file: {}", err);
            }

            for port in open_ports {
                // Get the service name or "unknown" if not found
                let service = get_service_by_port(port).unwrap_or("<unknown>");

                let line = format!("{}  open  {}\n", port, service);
                if let Err(err) = file.write_all(line.as_bytes()).await {
                    eprintln!("Failed to write to file: {}", err);
                }
            }

            println!("\nResults saved to {}", args.output_filename);
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
    println!("Starting BadMap {}", option_env!("CARGO_PKG_VERSION").unwrap_or("<uknown>"));

    let target: String = get_target(&args).await;
    if !args.domain.is_empty() {
        println!("BadMap Scan Report for {} ({})\n", args.domain, target);
    } else {
        println!("BadMap Scan Report for {}\n", target);
    }

    let open_ports: Vec<u16> = scan_ports(target.clone()).await;

    write_output_file(open_ports, target.clone(), &args).await;
}
