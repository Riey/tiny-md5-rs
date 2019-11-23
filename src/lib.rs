#![cfg_attr(test, feature(test))]

#[cfg(test)]
extern crate test;

use std::io::Read;

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const R: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const G: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8,
    13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9,
];

struct MD5State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl MD5State {
    #[inline]
    pub const fn new() -> Self {
        Self {
            a: 0x67452301,
            b: 0xEFCDAB89,
            c: 0x98BADCFE,
            d: 0x10325476,
        }
    }

    pub fn process(&mut self, chunk: &[u8; 64]) {
        let chunk: &[u32; 16] = unsafe { std::mem::transmute(chunk) };

        let mut a = self.a;
        let mut b = self.b;
        let mut c = self.c;
        let mut d = self.d;

        macro_rules! step {
            ($base:expr, $formulation:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
                step!(@$base + 0;  $formulation, $a, $b, $c, $d);
                step!(@$base + 1;  $formulation, $a, $b, $c, $d);
                step!(@$base + 2;  $formulation, $a, $b, $c, $d);
                step!(@$base + 3;  $formulation, $a, $b, $c, $d);
                step!(@$base + 4;  $formulation, $a, $b, $c, $d);
                step!(@$base + 5;  $formulation, $a, $b, $c, $d);
                step!(@$base + 6;  $formulation, $a, $b, $c, $d);
                step!(@$base + 7;  $formulation, $a, $b, $c, $d);
                step!(@$base + 8;  $formulation, $a, $b, $c, $d);
                step!(@$base + 9;  $formulation, $a, $b, $c, $d);
                step!(@$base + 10; $formulation, $a, $b, $c, $d);
                step!(@$base + 11; $formulation, $a, $b, $c, $d);
                step!(@$base + 12; $formulation, $a, $b, $c, $d);
                step!(@$base + 13; $formulation, $a, $b, $c, $d);
                step!(@$base + 14; $formulation, $a, $b, $c, $d);
                step!(@$base + 15; $formulation, $a, $b, $c, $d);
            };
            (@$i:expr; $formulation:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
                let f = $formulation.wrapping_add(a).wrapping_add(K[$i]).wrapping_add(chunk[G[$i]]);
                $a = $d;
                $d = $c;
                $c = $b;
                $b = $b.wrapping_add(f.rotate_left(R[$i]));
            };
        }

        step!(0, d ^ (b & (c ^ d)), a, b, c, d);
        step!(16, c ^ (d & (b ^ c)), a, b, c, d);
        step!(32, b ^ c ^ d, a, b, c, d);
        step!(48, c ^ (b | !d), a, b, c, d);

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
    }

    #[inline]
    pub fn digest(&self) -> [u8; 16] {
        let mut ret = [0; 16];

        unsafe {
            let ptr = ret.as_mut_ptr() as *mut u32;
            *ptr.add(0) = self.a;
            *ptr.add(1) = self.b;
            *ptr.add(2) = self.c;
            *ptr.add(3) = self.d;
        }

        ret
    }
}

pub fn hash(mut input: impl Read) -> [u8; 16] {
    let mut total_len = 0;
    let mut state = MD5State::new();
    let mut buf = [0u8; 64];

    loop {
        let len = input.read(&mut buf[..]).unwrap();
        total_len += len;

        if len == 64 {
            state.process(&buf);
        } else {
            let rem = total_len % 64;
            buf[rem] = 1 << 7;
            for i in rem + 1..64 - 8 {
                buf[i] = 0;
            }
            unsafe {
                *(buf.as_mut_ptr().add(56) as *mut u64) = (total_len * 8) as u64;
            }
            state.process(&buf);
            break;
        }
    }

    state.digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_md5() {
        assert_eq!(
            hex::encode(hash(&b"md5"[..])),
            "1bc29b36f623ba82aaf6724fd3b16718"
        );
        assert_eq!(
            hex::encode(hash(&b""[..])),
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
