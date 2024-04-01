use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "REDIS-TOOLS", about = "A CLI tool to send commands to redis")]
pub struct Options {
    #[structopt(short, long)]
    pub google: Option<Vec<String>>,
    #[structopt(short, long)]
    pub cookie_key : Option<String>
}