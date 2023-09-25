use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Name of the person to greet
    #[arg(
        short,
        long,
        default_value = "config.toml",
        value_name = "CONFIG_FILE",
        help = "Specify the config file"
    )]
    pub config: String,
}
