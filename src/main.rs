use tiny_md5_rs::hash_to_hex;
use std::env;
use std::fs;
use std::io::{self, BufReader, Write};

fn main() -> io::Result<()> {
    let ret = if let Some(file) = env::args()
        .skip(1)
        .find(|arg| std::path::Path::new(arg).exists())
    {
        let file = fs::File::open(file)?;
        let mmap = unsafe { memmap::MmapOptions::new().map(&file) }?;
        hash_to_hex(&*mmap)
    } else {
        hash_to_hex(BufReader::with_capacity(1024 * 512, io::stdin()))
    };

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(&ret)?;
    stdout.write_all(b"\n")?;

    Ok(())
}
