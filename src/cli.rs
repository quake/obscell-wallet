use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "obscell-wallet")]
#[command(author = "quake")]
#[command(version)]
#[command(about = "A TUI wallet for obscell privacy tokens on Nervos CKB")]
pub struct Args {
    /// Tick rate in ticks per second
    #[arg(short, long, default_value_t = 4.0)]
    pub tick_rate: f64,

    /// Frame rate in frames per second
    #[arg(short, long, default_value_t = 60.0)]
    pub frame_rate: f64,

    /// Network to connect to (testnet, mainnet, devnet)
    /// If not specified, uses last selected network or defaults to testnet
    #[arg(short, long)]
    pub network: Option<String>,

    /// Custom RPC URL (overrides network default)
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Data directory path
    #[arg(long)]
    pub data_dir: Option<String>,
}

impl Args {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
