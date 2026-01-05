//! Request/response pipeline architecture

use crate::Result;

/// Pipeline stage trait
pub trait PipelineStage: Send + Sync {
    fn name(&self) -> &str;
}

/// Request pipeline
pub struct RequestPipeline {
    stages: Vec<Box<dyn PipelineStage>>,
}

impl RequestPipeline {
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    pub fn add_stage(&mut self, stage: Box<dyn PipelineStage>) {
        self.stages.push(stage);
    }

    pub async fn execute(&self) -> Result<()> {
        // TODO: Implement pipeline execution
        Ok(())
    }
}
