use md5_rs::hash;
use std::env;
use std::fs;
use std::io::{self, BufReader};

fn main() -> io::Result<()> {
    let ret = if let Some(file) = env::args()
        .skip(1)
        .find(|arg| std::path::Path::new(arg).exists())
    {
        let file = fs::File::open(file)?;
        hash(BufReader::with_capacity(1024 * 512, file))
    } else {
        hash(BufReader::with_capacity(1024 * 512, io::stdin()))
    };

    println!("{}", hex::encode(ret));

    Ok(())
}
