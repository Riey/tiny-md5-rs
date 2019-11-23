use md5_rs::hash;
use std::fs;
use std::io::{self, BufReader};
use std::env;

fn main() -> io::Result<()> {
    let ret = if let Some(file) = env::args().skip(1).next() {
        println!("Read from {}", file);
        hash(BufReader::with_capacity(1024 * 1024, fs::File::open(file)?))
    } else {
        hash(io::stdin())
    };

    println!("{}", hex::encode(ret));

    Ok(())
}

