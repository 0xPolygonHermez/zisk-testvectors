use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use zisk_sdk::{
    AsmOptions, EmbeddedClient, ExecutorKind, GuestProgram, ProverClient,
    VerifyConstraintsExtension, ZiskStdin,
};

pub struct ProgramRunner {
    pub backend: Option<EmbeddedClient>,
    pub executor: ExecutorKind,
}

pub struct RunOptions {
    pub emulator: bool,
    pub proving_key: Option<PathBuf>,
    pub unlock_mapped_memory: bool,
    pub gpu: bool,
}

impl ProgramRunner {
    pub fn new(opts: &RunOptions) -> Result<Self> {
        let mut builder = ProverClient::embedded();

        if !opts.emulator {
            let asm_opts = if opts.unlock_mapped_memory {
                AsmOptions::default().unlock_mapped_memory()
            } else {
                AsmOptions::default()
            };
            builder = builder.assembly().asm_options(asm_opts);
        }

        if let Some(pk) = opts.proving_key.clone() {
            builder = builder.proving_key(pk);
        }

        if opts.gpu {
            builder = builder.gpu();
        }

        let runner = Self {
            backend: Some(builder.build().context("Failed to build EmbeddedClient")?),
            executor: if opts.emulator { ExecutorKind::Emulator } else { ExecutorKind::Assembly },
        };

        Ok(runner)
    }

    /// Run ROM setup (call once before executing any inputs)
    pub async fn setup(&self, program: &GuestProgram) -> Result<()> {
        let client =
            self.backend.as_ref().ok_or_else(|| anyhow::anyhow!("Client is not set up"))?;

        client.setup(program).run()?.await?;
        Ok(())
    }

    /// Emulate the execution of program with the given input (or empty stdin if `None`).
    pub async fn emulate(&self, program: &GuestProgram, input_file: Option<&Path>) -> Result<()> {
        let stdin = load_stdin(input_file)?;

        let client =
            self.backend.as_ref().ok_or_else(|| anyhow::anyhow!("Client is not set up"))?;

        client.execute(program, stdin).executor(self.executor).run()?.await?;
        Ok(())
    }

    /// Verify constraints for the program with the given input (or empty stdin if `None`).
    pub async fn verify_constraints(
        &self,
        program: &GuestProgram,
        input_file: Option<&Path>,
    ) -> Result<()> {
        let stdin = load_stdin(input_file)?;

        let client =
            self.backend.as_ref().ok_or_else(|| anyhow::anyhow!("Client is not set up"))?;

        client.verify_constraints(program, stdin).run()?.await?;
        Ok(())
    }
}

fn load_stdin(input_file: Option<&Path>) -> Result<ZiskStdin> {
    match input_file {
        Some(p) => ZiskStdin::from_file(p)
            .with_context(|| format!("Failed to load input file {}", p.display())),
        None => Ok(ZiskStdin::new()),
    }
}

/// Collect `.bin` input files from `program.inputs_dir()`.
///
/// Returns `vec![None]` if the directory doesn't exist or has no `.bin` files —
/// meaning the program runs once with empty stdin. Otherwise returns one
/// `Some(path)` per input, sorted by filename.
pub fn collect_inputs(inputs_dir: &Path) -> Result<Vec<Option<PathBuf>>> {
    if !inputs_dir.is_dir() {
        return Ok(vec![None]);
    }
    let mut bins: Vec<PathBuf> = std::fs::read_dir(inputs_dir)
        .with_context(|| format!("Failed to read {}", inputs_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("bin"))
        .collect();
    bins.sort();
    if bins.is_empty() {
        Ok(vec![None])
    } else {
        Ok(bins.into_iter().map(Some).collect())
    }
}
