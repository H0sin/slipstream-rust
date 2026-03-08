mod dns;
mod error;
mod pacing;
mod pinning;
mod runtime;
mod streams;
mod tunnel;

use clap::{parser::ValueSource, ArgGroup, CommandFactory, FromArgMatches, Parser};
use slipstream_core::{
    cli::{exit_with_error, exit_with_message, init_logging, unwrap_or_exit},
    normalize_domain, parse_host_port, parse_host_port_parts, sip003, AddressKind, HostPort,
};
use slipstream_ffi::{ClientConfig, ResolverMode, ResolverSpec};
use tokio::runtime::Builder;

use runtime::run_client;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "slipstream-client - A high-performance covert channel over DNS (client)",
    group(
        ArgGroup::new("resolvers")
            .multiple(true)
            .args(["resolver", "authoritative"])
    )
)]
struct Args {
    /// Local TCP listen address [default: ::]
    #[arg(long = "tcp-listen-host", default_value = "::")]
    tcp_listen_host: String,

    /// Local TCP listen port [default: 5201]
    #[arg(long = "tcp-listen-port", short = 'l', default_value_t = 5201)]
    tcp_listen_port: u16,

    /// Recursive DNS resolver (IP:PORT). May be repeated for multi-resolver balancing
    #[arg(long = "resolver", short = 'r', value_parser = parse_resolver)]
    resolver: Vec<HostPort>,

    /// QUIC congestion control algorithm
    #[arg(
        long = "congestion-control",
        short = 'c',
        value_parser = ["bbr", "dcubic"]
    )]
    congestion_control: Option<String>,

    /// Authoritative DNS resolver (IP:PORT). May be repeated
    #[arg(long = "authoritative", value_parser = parse_resolver)]
    authoritative: Vec<HostPort>,

    /// Enable Generic Segmentation Offload (Linux only)
    #[arg(
        short = 'g',
        long = "gso",
        num_args = 0..=1,
        default_value_t = false,
        default_missing_value = "true"
    )]
    gso: bool,

    /// Tunnel domain(s). May be repeated for multi-domain load balancing
    #[arg(long = "domain", short = 'd', value_parser = parse_domain)]
    domains: Vec<String>,

    /// Path to server TLS certificate for pinning (DER or PEM)
    #[arg(long = "cert", value_name = "PATH")]
    cert: Option<String>,

    /// QUIC keep-alive interval in milliseconds [default: 400]
    #[arg(long = "keep-alive-interval", short = 't', default_value_t = 400)]
    keep_alive_interval: u16,

    /// Log raw DNS poll packets
    #[arg(long = "debug-poll")]
    debug_poll: bool,

    /// Log stream-level events
    #[arg(long = "debug-streams")]
    debug_streams: bool,

    /// Path to file containing IP ranges for resolver scanning (one range per line: CIDR, dash-range, or single IP)
    #[arg(long = "scan-file", value_name = "PATH")]
    scan_file: Option<String>,

    /// Path to JSON cache file for persisting discovered resolvers [default: scan-cache.json]
    #[arg(long = "scan-cache", value_name = "PATH", default_value = "scan-cache.json")]
    scan_cache: String,

    /// Interval between resolver scan rounds in seconds [default: 300]
    #[arg(long = "scan-interval", default_value_t = 300)]
    scan_interval: u64,

    /// Maximum number of resolvers to discover via scanning [default: 5]
    #[arg(long = "scan-max", default_value_t = 5)]
    scan_max: usize,

    /// Number of IPs to probe per scan batch [default: 50]
    #[arg(long = "scan-batch", default_value_t = 50)]
    scan_batch: usize,

}

fn main() {
    init_logging();
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    let sip003_env = unwrap_or_exit(sip003::read_sip003_env(), "SIP003 env error", 2);
    if sip003_env.is_present() {
        tracing::info!("SIP003 env detected; applying SS_* overrides with CLI precedence");
    }

    let tcp_listen_host_provided = cli_provided(&matches, "tcp_listen_host");
    let tcp_listen_port_provided = cli_provided(&matches, "tcp_listen_port");
    let (tcp_listen_host, tcp_listen_port) = unwrap_or_exit(
        sip003::select_host_port(
            &args.tcp_listen_host,
            args.tcp_listen_port,
            tcp_listen_host_provided,
            tcp_listen_port_provided,
            sip003_env.local_host.as_deref(),
            sip003_env.local_port.as_deref(),
            "SS_LOCAL",
        ),
        "SIP003 env error",
        2,
    );

    let domains = if !args.domains.is_empty() {
        args.domains.clone()
    } else {
        let option_domains = unwrap_or_exit(
            parse_domains_from_options(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        );
        if !option_domains.is_empty() {
            option_domains
        } else {
            exit_with_message("At least one domain is required", 2);
        }
    };

    let cli_has_resolvers = has_cli_resolvers(&matches);
    let resolvers = if cli_has_resolvers {
        unwrap_or_exit(build_resolvers(&matches, true), "Resolver error", 2)
    } else {
        let resolver_options = unwrap_or_exit(
            parse_resolvers_from_options(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        );
        if !resolver_options.resolvers.is_empty() {
            resolver_options.resolvers
        } else {
            let sip003_remote = unwrap_or_exit(
                sip003::parse_endpoint(
                    sip003_env.remote_host.as_deref(),
                    sip003_env.remote_port.as_deref(),
                    "SS_REMOTE",
                ),
                "SIP003 env error",
                2,
            );
            if let Some(endpoint) = &sip003_remote {
                let mode = if resolver_options.authoritative_remote {
                    ResolverMode::Authoritative
                } else {
                    ResolverMode::Recursive
                };
                let resolver = unwrap_or_exit(
                    parse_host_port_parts(&endpoint.host, endpoint.port, AddressKind::Resolver),
                    "SIP003 env error",
                    2,
                );
                vec![ResolverSpec { resolver, mode }]
            } else {
                exit_with_message("At least one resolver is required", 2);
            }
        }
    };

    let congestion_control = if args.congestion_control.is_some() {
        args.congestion_control.clone()
    } else {
        unwrap_or_exit(
            parse_congestion_control(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        )
    };

    let cert = if args.cert.is_some() {
        args.cert.clone()
    } else {
        sip003::last_option_value(&sip003_env.plugin_options, "cert")
    };
    if cert.is_none() {
        tracing::warn!(
            "Server certificate pinning is disabled; this allows MITM. Provide --cert to pin the server leaf, or dismiss this if your underlying tunnel provides authentication."
        );
    }

    let keep_alive_interval = if cli_provided(&matches, "keep_alive_interval") {
        args.keep_alive_interval
    } else {
        let keep_alive_override = unwrap_or_exit(
            parse_keep_alive_interval(&sip003_env.plugin_options),
            "SIP003 env error",
            2,
        );
        keep_alive_override.unwrap_or(args.keep_alive_interval)
    };

    let config = ClientConfig {
        tcp_listen_host: &tcp_listen_host,
        tcp_listen_port,
        resolvers: &resolvers,
        congestion_control: congestion_control.as_deref(),
        gso: args.gso,
        domains: &domains,
        cert: cert.as_deref(),
        keep_alive_interval: keep_alive_interval as usize,
        debug_poll: args.debug_poll,
        debug_streams: args.debug_streams,
        scan_file: args.scan_file.as_deref(),
        scan_cache: Some(args.scan_cache.as_str()),
        scan_interval_secs: args.scan_interval,
        scan_max_resolvers: args.scan_max,
        scan_batch_size: args.scan_batch,
    };

    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to build Tokio runtime");
    match runtime.block_on(run_client(&config)) {
        Ok(code) => std::process::exit(code),
        Err(err) => exit_with_error("Client error", err, 1),
    }
}

fn parse_domain(input: &str) -> Result<String, String> {
    normalize_domain(input).map_err(|err| err.to_string())
}

fn parse_resolver(input: &str) -> Result<HostPort, String> {
    parse_host_port(input, 53, AddressKind::Resolver).map_err(|err| err.to_string())
}

fn build_resolvers(matches: &clap::ArgMatches, require: bool) -> Result<Vec<ResolverSpec>, String> {
    let mut ordered = Vec::new();
    collect_resolvers(matches, "resolver", ResolverMode::Recursive, &mut ordered)?;
    collect_resolvers(
        matches,
        "authoritative",
        ResolverMode::Authoritative,
        &mut ordered,
    )?;
    if ordered.is_empty() && require {
        return Err("At least one resolver is required".to_string());
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    Ok(ordered.into_iter().map(|(_, spec)| spec).collect())
}

fn collect_resolvers(
    matches: &clap::ArgMatches,
    name: &str,
    mode: ResolverMode,
    ordered: &mut Vec<(usize, ResolverSpec)>,
) -> Result<(), String> {
    let indices: Vec<usize> = matches.indices_of(name).into_iter().flatten().collect();
    let values: Vec<HostPort> = matches
        .get_many::<HostPort>(name)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if indices.len() != values.len() {
        return Err(format!("Mismatched {} arguments", name));
    }
    for (idx, resolver) in indices.into_iter().zip(values) {
        ordered.push((idx, ResolverSpec { resolver, mode }));
    }
    Ok(())
}

fn cli_provided(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn has_cli_resolvers(matches: &clap::ArgMatches) -> bool {
    matches
        .get_many::<HostPort>("resolver")
        .map(|values| values.len() > 0)
        .unwrap_or(false)
        || matches
            .get_many::<HostPort>("authoritative")
            .map(|values| values.len() > 0)
            .unwrap_or(false)
}

fn parse_domains_from_options(options: &[sip003::Sip003Option]) -> Result<Vec<String>, String> {
    let mut domains = None;
    for option in options {
        if option.key == "domain" {
            if domains.is_some() {
                return Err("SIP003 domain option must not be repeated".to_string());
            }
            let entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
            let mut parsed = Vec::new();
            for entry in entries {
                let normalized = normalize_domain(&entry).map_err(|err| err.to_string())?;
                parsed.push(normalized);
            }
            domains = Some(parsed);
        }
    }
    Ok(domains.unwrap_or_default())
}

struct ResolverOptions {
    resolvers: Vec<ResolverSpec>,
    authoritative_remote: bool,
}

fn parse_resolvers_from_options(
    options: &[sip003::Sip003Option],
) -> Result<ResolverOptions, String> {
    let mut ordered = Vec::new();
    let mut authoritative_remote = false;
    for option in options {
        let mode = match option.key.as_str() {
            "resolver" => ResolverMode::Recursive,
            "authoritative" => ResolverMode::Authoritative,
            _ => continue,
        };
        let trimmed = option.value.trim();
        if trimmed.is_empty() {
            if mode == ResolverMode::Authoritative {
                authoritative_remote = true;
                continue;
            }
            return Err("Empty resolver value is not allowed".to_string());
        }
        let entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
        for entry in entries {
            let resolver = parse_host_port(&entry, 53, AddressKind::Resolver)
                .map_err(|err| err.to_string())?;
            ordered.push(ResolverSpec { resolver, mode });
        }
    }
    Ok(ResolverOptions {
        resolvers: ordered,
        authoritative_remote,
    })
}

fn parse_congestion_control(options: &[sip003::Sip003Option]) -> Result<Option<String>, String> {
    let mut last = None;
    for option in options {
        if option.key == "congestion-control" {
            let value = option.value.trim();
            if value != "bbr" && value != "dcubic" {
                return Err(format!("Invalid congestion-control value: {}", value));
            }
            last = Some(value.to_string());
        }
    }
    Ok(last)
}

fn parse_keep_alive_interval(options: &[sip003::Sip003Option]) -> Result<Option<u16>, String> {
    let mut last = None;
    for option in options {
        if option.key == "keep-alive-interval" {
            let value = option.value.trim();
            let parsed = value
                .parse::<u16>()
                .map_err(|_| format!("Invalid keep-alive-interval value: {}", value))?;
            last = Some(parsed);
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_ordered_resolvers() {
        let matches = Args::command()
            .try_get_matches_from([
                "slipstream-client",
                "--domain",
                "example.com",
                "--resolver",
                "1.1.1.1",
                "--authoritative",
                "2.2.2.2",
                "--resolver",
                "3.3.3.3:5353",
            ])
            .expect("matches should parse");
        let resolvers = build_resolvers(&matches, true).expect("resolvers should parse");
        assert_eq!(resolvers.len(), 3);
        assert_eq!(resolvers[0].resolver.host, "1.1.1.1");
        assert_eq!(resolvers[0].resolver.port, 53);
        assert_eq!(resolvers[0].mode, ResolverMode::Recursive);
        assert_eq!(resolvers[1].resolver.host, "2.2.2.2");
        assert_eq!(resolvers[1].mode, ResolverMode::Authoritative);
        assert_eq!(resolvers[2].resolver.host, "3.3.3.3");
        assert_eq!(resolvers[2].resolver.port, 5353);
    }

    #[test]
    fn maps_authoritative_first() {
        let matches = Args::command()
            .try_get_matches_from([
                "slipstream-client",
                "--domain",
                "example.com",
                "--authoritative",
                "8.8.8.8",
                "--resolver",
                "9.9.9.9",
            ])
            .expect("matches should parse");
        let resolvers = build_resolvers(&matches, true).expect("resolvers should parse");
        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].resolver.host, "8.8.8.8");
        assert_eq!(resolvers[0].mode, ResolverMode::Authoritative);
        assert_eq!(resolvers[1].resolver.host, "9.9.9.9");
        assert_eq!(resolvers[1].mode, ResolverMode::Recursive);
    }

    #[test]
    fn parses_plugin_resolvers_in_order() {
        let options = vec![
            sip003::Sip003Option {
                key: "resolver".to_string(),
                value: "1.1.1.1,2.2.2.2:5353".to_string(),
            },
            sip003::Sip003Option {
                key: "authoritative".to_string(),
                value: "3.3.3.3".to_string(),
            },
            sip003::Sip003Option {
                key: "resolver".to_string(),
                value: "4.4.4.4".to_string(),
            },
        ];
        let parsed = parse_resolvers_from_options(&options).expect("options should parse");
        assert_eq!(parsed.resolvers.len(), 4);
        assert_eq!(parsed.resolvers[0].resolver.host, "1.1.1.1");
        assert_eq!(parsed.resolvers[0].mode, ResolverMode::Recursive);
        assert_eq!(parsed.resolvers[1].resolver.host, "2.2.2.2");
        assert_eq!(parsed.resolvers[1].resolver.port, 5353);
        assert_eq!(parsed.resolvers[2].resolver.host, "3.3.3.3");
        assert_eq!(parsed.resolvers[2].mode, ResolverMode::Authoritative);
        assert_eq!(parsed.resolvers[3].resolver.host, "4.4.4.4");
        assert!(!parsed.authoritative_remote);
    }

    #[test]
    fn plugin_domain_single_entry() {
        let options = vec![sip003::Sip003Option {
            key: "domain".to_string(),
            value: "example.com".to_string(),
        }];
        let domains = parse_domains_from_options(&options).expect("options should parse");
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "example.com");
    }

    #[test]
    fn plugin_domain_rejects_repeated_option() {
        let options = vec![
            sip003::Sip003Option {
                key: "domain".to_string(),
                value: "example.com".to_string(),
            },
            sip003::Sip003Option {
                key: "domain".to_string(),
                value: "example.net".to_string(),
            },
        ];
        assert!(parse_domains_from_options(&options).is_err());
    }

    #[test]
    fn plugin_domain_accepts_multiple_entries() {
        let options = vec![sip003::Sip003Option {
            key: "domain".to_string(),
            value: "example.com,example.net".to_string(),
        }];
        let domains = parse_domains_from_options(&options).expect("options should parse");
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0], "example.com");
        assert_eq!(domains[1], "example.net");
    }

    #[test]
    fn authoritative_flag_applies_to_remote() {
        let options = vec![sip003::Sip003Option {
            key: "authoritative".to_string(),
            value: "".to_string(),
        }];
        let parsed = parse_resolvers_from_options(&options).expect("options should parse");
        assert!(parsed.resolvers.is_empty());
        assert!(parsed.authoritative_remote);
    }
}
