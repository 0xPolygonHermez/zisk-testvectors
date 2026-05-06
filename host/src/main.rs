use anyhow::Result;
use clap::Parser;
use tracing::{error, info, warn};
use zisk_sdk::{setup_logger, VerboseMode};

mod cli;
mod elfs;
mod runner;

use cli::{Action, Cli, Program};
use elfs::elf_for;
use runner::{collect_inputs, ProgramRunner, RunOptions};

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger(VerboseMode::Info);

    let cli = Cli::parse();

    match (cli.action, cli.proving_key.is_some()) {
        (Action::Emulate, true) => {
            warn!("The proving key is ignored when action is `emulate`");
        }
        (Action::VerifyConstraints, false) => {
            anyhow::bail!("A proving key is required when action is `verify-constraints`");
        }
        _ => {}
    }

    let programs: Vec<Program> = cli.resolve_programs();

    info!("ZisK Host");
    info!(" Action: {:?}", cli.action);
    info!(" Backend: {}", if cli.emulator { "Emulator" } else { "Assembly" });
    info!(" Programs: {}", programs.len());

    let opts = RunOptions {
        emulator: cli.emulator,
        proving_key: cli.proving_key,
        unlock_mapped_memory: cli.unlock_mapped_memory,
        gpu: cli.gpu,
    };

    let runner = match ProgramRunner::new(&opts) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to initialize ProgramRunner: {e}");
            return Err(e);
        }
    };

    let total = programs.len();
    let mut passed = 0;
    let mut failed = 0;

    for (i, program) in programs.iter().copied().enumerate() {
        let label = format!("[{}/{}] {}", i + 1, total, program.name());
        info!("{label}: setting up...");

        let program_elf = elf_for(program);

        if let Err(e) = runner.setup(&program_elf).await {
            error!("{label}: setup failed: {e}");
            failed += 1;
            continue;
        }

        let inputs_dir = program.inputs_dir();
        let inputs = match collect_inputs(&inputs_dir) {
            Ok(v) => v,
            Err(e) => {
                error!("{label}: {e}");
                failed += 1;
                continue;
            }
        };

        match inputs.as_slice() {
            [None] => info!("{label}: no inputs (running once with empty stdin)"),
            _ => info!("{label}: {} input(s) from {}", inputs.len(), inputs_dir.display()),
        }

        for input in inputs {
            let input_label = match &input {
                Some(p) => {
                    format!("{label} {}", p.file_name().and_then(|s| s.to_str()).unwrap_or("?"))
                }
                None => label.clone(),
            };

            info!("{input_label}: running {:?}...", cli.action);

            let result = match cli.action {
                Action::Emulate => runner.emulate(&program_elf, input.as_deref()).await,
                Action::VerifyConstraints => {
                    runner.verify_constraints(&program_elf, input.as_deref()).await
                }
            };

            match result {
                Ok(_) => {
                    info!("{input_label}: {:?} ok", cli.action);
                    passed += 1;
                }
                Err(e) => {
                    error!("{input_label}: {:?} failed: {e}", cli.action);
                    failed += 1;
                }
            }
        }
    }

    info!("");
    info!("Summary: {passed} passed, {failed} failed");

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}
