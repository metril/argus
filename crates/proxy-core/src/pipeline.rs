//! Request/response pipeline architecture
//!
//! The pipeline provides a flexible framework for processing HTTP requests and responses
//! through a series of stages. Each stage can inspect, modify, or block the request/response.

use crate::{Error, Result};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};

/// Context passed through the pipeline
#[derive(Clone)]
pub struct PipelineContext {
    /// Client address
    pub client_addr: SocketAddr,
    /// Request method
    pub method: Method,
    /// Request URI
    pub uri: Uri,
    /// HTTP version
    pub version: Version,
    /// Custom metadata that stages can use
    pub metadata: std::collections::HashMap<String, String>,
}

impl PipelineContext {
    pub fn new(client_addr: SocketAddr, method: Method, uri: Uri, version: Version) -> Self {
        Self {
            client_addr,
            method,
            uri,
            version,
            metadata: std::collections::HashMap::new(),
        }
    }
}

/// Result of a pipeline stage execution
#[derive(Debug)]
pub enum StageResult {
    /// Continue to next stage
    Continue,
    /// Block the request with a response
    Block(Response<http_body_util::Full<Bytes>>),
    /// Skip remaining stages and forward request
    Forward,
}

/// Request pipeline stage trait
#[async_trait::async_trait]
pub trait RequestStage: Send + Sync {
    /// Stage name for logging
    fn name(&self) -> &str;

    /// Execute the stage
    async fn execute(
        &self,
        ctx: &mut PipelineContext,
        headers: &mut HeaderMap,
    ) -> Result<StageResult>;
}

/// Response pipeline stage trait
#[async_trait::async_trait]
pub trait ResponseStage: Send + Sync {
    /// Stage name for logging
    fn name(&self) -> &str;

    /// Execute the stage on the response
    async fn execute(
        &self,
        ctx: &PipelineContext,
        status: StatusCode,
        headers: &mut HeaderMap,
        body: &mut Bytes,
    ) -> Result<StageResult>;
}

/// Request processing pipeline
pub struct RequestPipeline {
    stages: Vec<Arc<dyn RequestStage>>,
}

impl RequestPipeline {
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
        }
    }

    /// Add a stage to the pipeline
    pub fn add_stage(&mut self, stage: Arc<dyn RequestStage>) {
        self.stages.push(stage);
    }

    /// Execute the pipeline
    pub async fn execute(
        &self,
        ctx: &mut PipelineContext,
        headers: &mut HeaderMap,
    ) -> Result<StageResult> {
        for stage in &self.stages {
            debug!("Executing request stage: {}", stage.name());

            match stage.execute(ctx, headers).await? {
                StageResult::Continue => {
                    // Continue to next stage
                    continue;
                }
                StageResult::Block(response) => {
                    info!("Request blocked by stage: {}", stage.name());
                    return Ok(StageResult::Block(response));
                }
                StageResult::Forward => {
                    debug!("Forwarding request from stage: {}", stage.name());
                    return Ok(StageResult::Forward);
                }
            }
        }

        // All stages passed, forward the request
        Ok(StageResult::Forward)
    }
}

impl Default for RequestPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Response processing pipeline
pub struct ResponsePipeline {
    stages: Vec<Arc<dyn ResponseStage>>,
}

impl ResponsePipeline {
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
        }
    }

    /// Add a stage to the pipeline
    pub fn add_stage(&mut self, stage: Arc<dyn ResponseStage>) {
        self.stages.push(stage);
    }

    /// Execute the pipeline
    pub async fn execute(
        &self,
        ctx: &PipelineContext,
        status: StatusCode,
        headers: &mut HeaderMap,
        body: &mut Bytes,
    ) -> Result<StageResult> {
        for stage in &self.stages {
            debug!("Executing response stage: {}", stage.name());

            match stage.execute(ctx, status, headers, body).await? {
                StageResult::Continue => {
                    // Continue to next stage
                    continue;
                }
                StageResult::Block(response) => {
                    info!("Response blocked by stage: {}", stage.name());
                    return Ok(StageResult::Block(response));
                }
                StageResult::Forward => {
                    debug!("Forwarding response from stage: {}", stage.name());
                    return Ok(StageResult::Forward);
                }
            }
        }

        // All stages passed
        Ok(StageResult::Continue)
    }
}

impl Default for ResponsePipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Example logging stage
pub struct LoggingStage;

#[async_trait::async_trait]
impl RequestStage for LoggingStage {
    fn name(&self) -> &str {
        "logging"
    }

    async fn execute(
        &self,
        ctx: &mut PipelineContext,
        _headers: &mut HeaderMap,
    ) -> Result<StageResult> {
        info!(
            "Request: {} {} from {}",
            ctx.method, ctx.uri, ctx.client_addr
        );
        Ok(StageResult::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Method;
    use std::net::{IpAddr, Ipv4Addr};

    struct TestStage {
        should_block: bool,
    }

    #[async_trait::async_trait]
    impl RequestStage for TestStage {
        fn name(&self) -> &str {
            "test"
        }

        async fn execute(
            &self,
            _ctx: &mut PipelineContext,
            _headers: &mut HeaderMap,
        ) -> Result<StageResult> {
            if self.should_block {
                Ok(StageResult::Block(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(http_body_util::Full::new(Bytes::from("Blocked")))
                        .unwrap(),
                ))
            } else {
                Ok(StageResult::Continue)
            }
        }
    }

    #[tokio::test]
    async fn test_pipeline_continue() {
        let mut pipeline = RequestPipeline::new();
        pipeline.add_stage(Arc::new(TestStage { should_block: false }));

        let mut ctx = PipelineContext::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            Method::GET,
            "http://example.com".parse().unwrap(),
            Version::HTTP_11,
        );
        let mut headers = HeaderMap::new();

        let result = pipeline.execute(&mut ctx, &mut headers).await.unwrap();
        assert!(matches!(result, StageResult::Forward));
    }

    #[tokio::test]
    async fn test_pipeline_block() {
        let mut pipeline = RequestPipeline::new();
        pipeline.add_stage(Arc::new(TestStage { should_block: true }));

        let mut ctx = PipelineContext::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            Method::GET,
            "http://example.com".parse().unwrap(),
            Version::HTTP_11,
        );
        let mut headers = HeaderMap::new();

        let result = pipeline.execute(&mut ctx, &mut headers).await.unwrap();
        assert!(matches!(result, StageResult::Block(_)));
    }
}
