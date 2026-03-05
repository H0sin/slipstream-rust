pub(crate) mod balancer;
pub(crate) mod debug;
pub(crate) mod health;
mod path;
mod poll;
pub(crate) mod resolver;
mod response;

pub(crate) use balancer::DomainBalancer;
pub(crate) use debug::maybe_report_debug;
pub(crate) use health::{HealthUpdate, TunnelSnapshot};
pub(crate) use path::{refresh_resolver_path, resolver_mode_to_c};
pub(crate) use poll::{expire_inflight_polls, send_poll_queries};
pub(crate) use resolver::{
    reset_resolver_path, resolve_resolvers,
    sockaddr_storage_to_socket_addr, ResolverState,
};
pub(crate) use response::{handle_dns_response_tunneled, TunneledResponseContext};
