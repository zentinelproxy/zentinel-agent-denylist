//! Denylist agent for Sentinel proxy
//!
//! This agent blocks requests based on configured deny rules for IPs, paths, and headers.

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, ConfigureEvent, Decision, RequestHeadersEvent,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::RwLock;
use tracing::{debug, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Denylist agent CLI arguments
#[derive(Parser, Debug)]
#[command(name = "denylist-agent")]
#[command(about = "Denylist agent for blocking requests based on IP, path, and header rules")]
struct Args {
    /// Unix socket path to listen on
    #[arg(short, long, default_value = "/tmp/sentinel-denylist.sock")]
    socket: String,

    /// Comma-separated list of IP addresses to block
    #[arg(long, value_delimiter = ',')]
    block_ips: Vec<String>,

    /// Comma-separated list of path prefixes to block
    #[arg(long, value_delimiter = ',')]
    block_paths: Vec<String>,

    /// Comma-separated list of User-Agent patterns to block
    #[arg(long, value_delimiter = ',')]
    block_user_agents: Vec<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

/// JSON configuration for dynamic reconfiguration via on_configure()
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DenylistConfigJson {
    /// IP addresses to block
    #[serde(default)]
    pub block_ips: Vec<String>,
    /// Path prefixes to block
    #[serde(default)]
    pub block_paths: Vec<String>,
    /// User-Agent patterns to block
    #[serde(default)]
    pub block_user_agents: Vec<String>,
}

/// Internal state for denylist configuration
struct DenylistState {
    /// Set of blocked IP addresses
    blocked_ips: HashSet<IpAddr>,
    /// Set of blocked path prefixes
    blocked_paths: Vec<String>,
    /// Set of blocked User-Agent patterns
    blocked_user_agents: Vec<String>,
}

/// Denylist agent handler
struct DenylistHandler {
    state: RwLock<DenylistState>,
}

impl DenylistHandler {
    /// Create a new denylist handler
    fn new(args: &Args) -> Self {
        // Parse blocked IPs
        let blocked_ips = args
            .block_ips
            .iter()
            .filter_map(|ip| match IpAddr::from_str(ip) {
                Ok(addr) => Some(addr),
                Err(e) => {
                    warn!("Invalid IP address '{}': {}", ip, e);
                    None
                }
            })
            .collect();

        Self {
            state: RwLock::new(DenylistState {
                blocked_ips,
                blocked_paths: args.block_paths.clone(),
                blocked_user_agents: args.block_user_agents.clone(),
            }),
        }
    }

    /// Reconfigure the agent with new settings
    fn reconfigure(&self, config: DenylistConfigJson) {
        // Parse blocked IPs
        let blocked_ips: HashSet<IpAddr> = config
            .block_ips
            .iter()
            .filter_map(|ip| match IpAddr::from_str(ip) {
                Ok(addr) => Some(addr),
                Err(e) => {
                    warn!("Invalid IP address '{}': {}", ip, e);
                    None
                }
            })
            .collect();

        if let Ok(mut state) = self.state.write() {
            if !config.block_ips.is_empty() {
                state.blocked_ips = blocked_ips;
            }
            if !config.block_paths.is_empty() {
                state.blocked_paths = config.block_paths;
            }
            if !config.block_user_agents.is_empty() {
                state.blocked_user_agents = config.block_user_agents;
            }
            info!("Denylist agent reconfigured");
        }
    }

    /// Check if an IP is blocked
    fn is_ip_blocked(&self, ip: &str) -> bool {
        if let Ok(addr) = IpAddr::from_str(ip) {
            if let Ok(state) = self.state.read() {
                return state.blocked_ips.contains(&addr);
            }
        }
        false
    }

    /// Check if a path is blocked
    fn is_path_blocked(&self, path: &str) -> bool {
        if let Ok(state) = self.state.read() {
            return state.blocked_paths.iter().any(|blocked| path.starts_with(blocked));
        }
        false
    }

    /// Check if a User-Agent is blocked
    fn is_user_agent_blocked(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();
        if let Ok(state) = self.state.read() {
            return state.blocked_user_agents
                .iter()
                .any(|pattern| ua_lower.contains(&pattern.to_lowercase()));
        }
        false
    }

    /// Create a deny response with a message
    fn create_deny_response(&self, message: String) -> AgentResponse {
        let mut response = AgentResponse::default_allow();
        response.decision = Decision::Block {
            status: 403,
            body: Some(message.clone()),
            headers: None,
        };
        response
            .routing_metadata
            .insert("deny_reason".to_string(), message);
        response
    }
}

#[async_trait]
impl AgentHandler for DenylistHandler {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        let config: DenylistConfigJson = match serde_json::from_value(event.config) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to parse denylist config: {}, using defaults", e);
                return AgentResponse::default_allow();
            }
        };

        self.reconfigure(config);
        info!("Denylist agent configured via on_configure");
        AgentResponse::default_allow()
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        debug!(
            "Processing request: {} {} from {}",
            event.method, event.uri, event.metadata.client_ip
        );

        // Check IP blocking
        if self.is_ip_blocked(&event.metadata.client_ip) {
            info!("Blocked request from IP: {}", event.metadata.client_ip);
            return self
                .create_deny_response(format!("IP {} is blocked", event.metadata.client_ip));
        }

        // Check path blocking
        if self.is_path_blocked(&event.uri) {
            info!("Blocked request to path: {}", event.uri);
            return self.create_deny_response(format!("Path {} is blocked", event.uri));
        }

        // Check User-Agent blocking
        if let Some(user_agents) = event.headers.get("user-agent") {
            // user_agents is Vec<String>, check first value
            if let Some(ua_str) = user_agents.first() {
                if self.is_user_agent_blocked(ua_str) {
                    info!("Blocked request with User-Agent: {}", ua_str);
                    return self
                        .create_deny_response(format!("User-Agent '{}' is blocked", ua_str));
                }
            }
        }

        // Allow the request if no rules match
        debug!("Request allowed");
        AgentResponse::default_allow()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    // Log configuration
    info!("Starting denylist agent");
    info!("Socket path: {}", args.socket);
    if !args.block_ips.is_empty() {
        info!("Blocking IPs: {:?}", args.block_ips);
    }
    if !args.block_paths.is_empty() {
        info!("Blocking paths: {:?}", args.block_paths);
    }
    if !args.block_user_agents.is_empty() {
        info!("Blocking User-Agents: {:?}", args.block_user_agents);
    }

    // Create handler
    let handler = DenylistHandler::new(&args);

    // Create and run agent server
    let server = AgentServer::new("denylist-agent", &args.socket, Box::new(handler));

    info!("Denylist agent ready");
    server.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_blocking() {
        let args = Args {
            socket: "/tmp/test.sock".to_string(),
            block_ips: vec!["192.168.1.100".to_string(), "10.0.0.1".to_string()],
            block_paths: vec![],
            block_user_agents: vec![],
            verbose: false,
        };

        let handler = DenylistHandler::new(&args);

        assert!(handler.is_ip_blocked("192.168.1.100"));
        assert!(handler.is_ip_blocked("10.0.0.1"));
        assert!(!handler.is_ip_blocked("192.168.1.101"));
        assert!(!handler.is_ip_blocked("invalid-ip"));
    }

    #[test]
    fn test_path_blocking() {
        let args = Args {
            socket: "/tmp/test.sock".to_string(),
            block_ips: vec![],
            block_paths: vec!["/admin".to_string(), "/api/private".to_string()],
            block_user_agents: vec![],
            verbose: false,
        };

        let handler = DenylistHandler::new(&args);

        assert!(handler.is_path_blocked("/admin"));
        assert!(handler.is_path_blocked("/admin/users"));
        assert!(handler.is_path_blocked("/api/private/data"));
        assert!(!handler.is_path_blocked("/api/public"));
        assert!(!handler.is_path_blocked("/"));
    }

    #[test]
    fn test_user_agent_blocking() {
        let args = Args {
            socket: "/tmp/test.sock".to_string(),
            block_ips: vec![],
            block_paths: vec![],
            block_user_agents: vec!["bot".to_string(), "scanner".to_string()],
            verbose: false,
        };

        let handler = DenylistHandler::new(&args);

        assert!(handler.is_user_agent_blocked("BadBot/1.0"));
        assert!(handler.is_user_agent_blocked("Mozilla/5.0 bot"));
        assert!(handler.is_user_agent_blocked("Security Scanner v2"));
        assert!(handler.is_user_agent_blocked("SCANNER"));
        assert!(!handler.is_user_agent_blocked("Mozilla/5.0"));
        assert!(!handler.is_user_agent_blocked("Chrome/120.0"));
    }
}
