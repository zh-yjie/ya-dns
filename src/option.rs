use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Specify the config file
    #[arg(
        short,
        long,
        value_name = "CONFIG_FILE",
        help = "Specify the config file. If not provided, it will search for config.toml, config.yaml, and config.yml in the current directory."
    )]
    pub config: Option<String>,
}
