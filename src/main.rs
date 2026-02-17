//! Denylist agent for Zentinel proxy (v2 protocol)
//!
//! This agent blocks requests based on configured deny rules for IPs, paths, and headers.

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use serde::{Deserialize, Serialize};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, DrainReason, GrpcAgentServerV2,
    HealthStatus, MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, AgentServer, Decision, EventType, RequestHeadersEvent,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tracing::{debug, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Denylist agent CLI arguments
#[derive(Parser, Debug)]
#[command(name = "denylist-agent")]
#[command(about = "Denylist agent for blocking requests based on IP, path, and header rules")]
struct Args {
    /// Unix socket path to listen on
    #[arg(short, long, default_value = "/tmp/zentinel-denylist.sock")]
    socket: String,

    /// gRPC address to listen on (e.g., "0.0.0.0:50051")
    #[arg(long)]
    grpc_address: Option<String>,

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

/// Denylist agent handler (v2 protocol)
struct DenylistHandler {
    state: RwLock<DenylistState>,
    /// Counter for requests processed
    requests_processed: AtomicU64,
    /// Counter for requests blocked
    requests_blocked: AtomicU64,
    /// Configuration version
    config_version: RwLock<Option<String>>,
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
            requests_processed: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            config_version: RwLock::new(None),
        }
    }

    /// Reconfigure the agent with new settings
    fn reconfigure(&self, config: DenylistConfigJson, version: Option<String>) {
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

        if let Ok(mut ver) = self.config_version.write() {
            *ver = version;
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
            return state
                .blocked_paths
                .iter()
                .any(|blocked| path.starts_with(blocked));
        }
        false
    }

    /// Check if a User-Agent is blocked
    fn is_user_agent_blocked(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();
        if let Ok(state) = self.state.read() {
            return state
                .blocked_user_agents
                .iter()
                .any(|pattern| ua_lower.contains(&pattern.to_lowercase()));
        }
        false
    }

    /// Create a deny response with a message
    fn create_deny_response(&self, message: String) -> AgentResponse {
        self.requests_blocked.fetch_add(1, Ordering::Relaxed);
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
impl AgentHandlerV2 for DenylistHandler {
    /// Returns agent capabilities for v2 protocol
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("denylist-agent", "Denylist Agent", env!("CARGO_PKG_VERSION"))
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::Configure)
            .with_features(AgentFeatures {
                config_push: true,
                health_reporting: true,
                metrics_export: true,
                concurrent_requests: 100,
                cancellation: true,
                ..Default::default()
            })
    }

    /// Handle configuration update from proxy (v2 signature)
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        let parsed_config: DenylistConfigJson = match serde_json::from_value(config) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to parse denylist config: {}, using defaults", e);
                return false;
            }
        };

        self.reconfigure(parsed_config, version);
        info!("Denylist agent configured via on_configure");
        true
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_processed.fetch_add(1, Ordering::Relaxed);

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

    /// Returns health status for v2 protocol
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy("denylist-agent")
    }

    /// Returns metrics report for v2 protocol
    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("denylist-agent", 10_000);

        report.counters.push(zentinel_agent_protocol::v2::CounterMetric::new(
            "denylist_requests_total",
            self.requests_processed.load(Ordering::Relaxed),
        ));

        report.counters.push(zentinel_agent_protocol::v2::CounterMetric::new(
            "denylist_requests_blocked_total",
            self.requests_blocked.load(Ordering::Relaxed),
        ));

        Some(report)
    }

    /// Handle shutdown request from proxy
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            "Shutdown requested: {:?}, grace period: {}ms",
            reason, grace_period_ms
        );
        // Agent can perform cleanup here
    }

    /// Handle drain request from proxy
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            "Drain requested: {:?}, duration: {}ms",
            reason, duration_ms
        );
        // Agent should stop accepting new requests and finish in-flight ones
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
    info!("Starting denylist agent v{}", env!("CARGO_PKG_VERSION"));
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

    // Run either gRPC or UDS server based on CLI args
    if let Some(grpc_addr) = &args.grpc_address {
        info!("gRPC address: {}", grpc_addr);
        let addr: std::net::SocketAddr = grpc_addr.parse()?;
        let server = GrpcAgentServerV2::new("denylist-agent", Box::new(handler));
        info!("Denylist agent ready (gRPC v2)");
        server.run(addr).await?;
    } else {
        info!("Socket path: {}", args.socket);
        // For UDS, we use v1 AgentServer with v2-compatible handler wrapper
        let server = AgentServer::new(
            "denylist-agent",
            &args.socket,
            Box::new(V2HandlerWrapper(handler)),
        );
        info!("Denylist agent ready (UDS)");
        server.run().await?;
    }

    Ok(())
}

/// Wrapper to use AgentHandlerV2 with v1 AgentServer (for UDS transport)
struct V2HandlerWrapper(DenylistHandler);

#[async_trait]
impl zentinel_agent_protocol::AgentHandler for V2HandlerWrapper {
    async fn on_configure(
        &self,
        event: zentinel_agent_protocol::ConfigureEvent,
    ) -> AgentResponse {
        let accepted = self.0.on_configure(event.config, None).await;
        if accepted {
            AgentResponse::default_allow()
        } else {
            let mut response = AgentResponse::default_allow();
            response
                .routing_metadata
                .insert("config_error".to_string(), "true".to_string());
            response
        }
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.0.on_request_headers(event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_args(
        block_ips: Vec<String>,
        block_paths: Vec<String>,
        block_user_agents: Vec<String>,
    ) -> Args {
        Args {
            socket: "/tmp/test.sock".to_string(),
            grpc_address: None,
            block_ips,
            block_paths,
            block_user_agents,
            verbose: false,
        }
    }

    #[test]
    fn test_ip_blocking() {
        let args = create_test_args(
            vec!["192.168.1.100".to_string(), "10.0.0.1".to_string()],
            vec![],
            vec![],
        );

        let handler = DenylistHandler::new(&args);

        assert!(handler.is_ip_blocked("192.168.1.100"));
        assert!(handler.is_ip_blocked("10.0.0.1"));
        assert!(!handler.is_ip_blocked("192.168.1.101"));
        assert!(!handler.is_ip_blocked("invalid-ip"));
    }

    #[test]
    fn test_path_blocking() {
        let args = create_test_args(
            vec![],
            vec!["/admin".to_string(), "/api/private".to_string()],
            vec![],
        );

        let handler = DenylistHandler::new(&args);

        assert!(handler.is_path_blocked("/admin"));
        assert!(handler.is_path_blocked("/admin/users"));
        assert!(handler.is_path_blocked("/api/private/data"));
        assert!(!handler.is_path_blocked("/api/public"));
        assert!(!handler.is_path_blocked("/"));
    }

    #[test]
    fn test_user_agent_blocking() {
        let args = create_test_args(
            vec![],
            vec![],
            vec!["bot".to_string(), "scanner".to_string()],
        );

        let handler = DenylistHandler::new(&args);

        assert!(handler.is_user_agent_blocked("BadBot/1.0"));
        assert!(handler.is_user_agent_blocked("Mozilla/5.0 bot"));
        assert!(handler.is_user_agent_blocked("Security Scanner v2"));
        assert!(handler.is_user_agent_blocked("SCANNER"));
        assert!(!handler.is_user_agent_blocked("Mozilla/5.0"));
        assert!(!handler.is_user_agent_blocked("Chrome/120.0"));
    }

    #[test]
    fn test_capabilities() {
        let args = create_test_args(vec![], vec![], vec![]);
        let handler = DenylistHandler::new(&args);
        let caps = handler.capabilities();

        assert_eq!(caps.agent_id, "denylist-agent");
        assert_eq!(caps.name, "Denylist Agent");
        assert!(caps.supports_event(EventType::RequestHeaders));
        assert!(caps.supports_event(EventType::Configure));
        assert!(caps.features.config_push);
        assert!(caps.features.health_reporting);
        assert!(caps.features.metrics_export);
    }

    #[test]
    fn test_health_status() {
        let args = create_test_args(vec![], vec![], vec![]);
        let handler = DenylistHandler::new(&args);
        let health = handler.health_status();

        assert!(health.is_healthy());
        assert_eq!(health.agent_id, "denylist-agent");
    }

    #[test]
    fn test_metrics_report() {
        let args = create_test_args(vec![], vec![], vec![]);
        let handler = DenylistHandler::new(&args);

        // Simulate some requests
        handler.requests_processed.fetch_add(10, Ordering::Relaxed);
        handler.requests_blocked.fetch_add(2, Ordering::Relaxed);

        let report = handler.metrics_report().expect("metrics report should exist");
        assert_eq!(report.agent_id, "denylist-agent");
        assert_eq!(report.counters.len(), 2);

        let processed = report
            .counters
            .iter()
            .find(|c| c.name == "denylist_requests_total")
            .expect("should have requests counter");
        assert_eq!(processed.value, 10);

        let blocked = report
            .counters
            .iter()
            .find(|c| c.name == "denylist_requests_blocked_total")
            .expect("should have blocked counter");
        assert_eq!(blocked.value, 2);
    }

    #[tokio::test]
    async fn test_on_configure_v2() {
        let args = create_test_args(vec![], vec![], vec![]);
        let handler = DenylistHandler::new(&args);

        let config = serde_json::json!({
            "block-ips": ["1.2.3.4"],
            "block-paths": ["/secret"],
            "block-user-agents": ["evil-bot"]
        });

        let accepted = handler
            .on_configure(config, Some("v1.0.0".to_string()))
            .await;
        assert!(accepted);

        assert!(handler.is_ip_blocked("1.2.3.4"));
        assert!(handler.is_path_blocked("/secret"));
        assert!(handler.is_user_agent_blocked("evil-bot"));

        // Check config version was stored
        let version = handler.config_version.read().unwrap();
        assert_eq!(*version, Some("v1.0.0".to_string()));
    }

    #[tokio::test]
    async fn test_on_configure_invalid() {
        let args = create_test_args(vec![], vec![], vec![]);
        let handler = DenylistHandler::new(&args);

        // Invalid config structure
        let config = serde_json::json!({
            "invalid_field": 123
        });

        // Should still succeed with empty config (all fields are optional with defaults)
        let accepted = handler.on_configure(config, None).await;
        assert!(accepted);
    }
}
