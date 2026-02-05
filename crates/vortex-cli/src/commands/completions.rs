//! Shell completions command

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::generate;

pub fn run(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = crate::Cli::command();
    generate(shell, &mut cmd, "vortex", &mut std::io::stdout());
    Ok(())
}
