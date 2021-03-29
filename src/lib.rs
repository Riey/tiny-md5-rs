#![cfg_attr(test, feature(test))]

#[cfg(test)]
extern crate test;

mod state;

use std::io::Read;

pub fn hash(mut input: impl Read) -> [u8; 16] {
    let mut state = state::MD5State::new();

    loop {
        match input.read(&mut state.buf[..]) {
            Err(_) => {
                return state.digest();
            }
            Ok(len) => {
                if len >= 64 {
                    state.total_len += 64;
                    state.process();
                } else {
                    unsafe { state.end(len) };
                    return state.digest();
                }
            }
        };
    }
}

pub fn hash_to_hex(input: impl Read) -> [u8; 32] {
    const HEX: [u8; 16] = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e',
        b'f',
    ];

    let hash = hash(input);
    let mut ret = [0; 32];

    for (i, b) in hash.iter().cloned().enumerate() {
        let higher = (b / 16) as usize;
        let lower = (b % 16) as usize;

        ret[i * 2] = HEX[higher];
        ret[i * 2 + 1] = HEX[lower];
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_md5() {
        assert_eq!(
            std::str::from_utf8(&hash_to_hex(&b"md5"[..])).unwrap(),
            "1bc29b36f623ba82aaf6724fd3b16718"
        );
        assert_eq!(
            std::str::from_utf8(&hash_to_hex(&b""[..])).unwrap(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }
}

#[cfg(test)]
mod benches {
    use super::*;

    #[bench]
    fn bench_1k(b: &mut test::Bencher) {
        let test = [1u8; 1024];
        b.bytes = test.len() as u64;

        b.iter(|| {
            hash(&test[..]);
        });
    }

    #[bench]
    fn bench_64k(b: &mut test::Bencher) {
        let test = [1u8; 64 * 1024];
        b.bytes = test.len() as u64;

        b.iter(|| {
            hash(&test[..]);
        });
    }
}
