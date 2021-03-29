pub struct MD5State {
    pub buf: [u8; 64],
    pub state: [u32; 4],
    pub total_len: usize,
}

impl MD5State {
    #[inline]
    pub const fn new() -> Self {
        Self {
            buf: [0; 64],
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            total_len: 0,
        }
    }

    #[inline(always)]
    /// # Safety
    ///
    /// `len` must less than 64
    pub unsafe fn end(&mut self, len: usize) {
        debug_assert!(len < 64);

        if len >= 64 {
            std::hint::unreachable_unchecked();
        }

        self.buf[len] = 1 << 7;
        if let Some(cnt) = 56usize.checked_sub(len + 1) {
            std::ptr::write_bytes(self.buf.as_mut_ptr().add(len + 1), 0, cnt);
        }
        self.buf
            .as_mut_ptr()
            .add(56)
            .cast::<u64>()
            .write((self.total_len + len) as u64 * 8);

        self.process();
    }

    pub fn process(&mut self) {
        let chunk: [u32; 16] = unsafe { std::mem::transmute(self.buf) };
        let [mut a, mut b, mut c, mut d] = self.state;

        macro_rules! step {
            ($base:expr, $formulation:ident) => {
                step!(@$base + 0;  a, b, c, d, $formulation);
                step!(@$base + 1;  d, a, b, c, $formulation);
                step!(@$base + 2;  c, d, a, b, $formulation);
                step!(@$base + 3;  b, c, d, a, $formulation);
                step!(@$base + 4;  a, b, c, d, $formulation);
                step!(@$base + 5;  d, a, b, c, $formulation);
                step!(@$base + 6;  c, d, a, b, $formulation);
                step!(@$base + 7;  b, c, d, a, $formulation);
                step!(@$base + 8;  a, b, c, d, $formulation);
                step!(@$base + 9;  d, a, b, c, $formulation);
                step!(@$base + 10; c, d, a, b, $formulation);
                step!(@$base + 11; b, c, d, a, $formulation);
                step!(@$base + 12; a, b, c, d, $formulation);
                step!(@$base + 13; d, a, b, c, $formulation);
                step!(@$base + 14; c, d, a, b, $formulation);
                step!(@$base + 15; b, c, d, a, $formulation);
            };
            (@$i:expr; $a:expr, $b:expr, $c:expr, $d:expr, $formulation:ident) => {
                $a = $formulation($b, $c, $d).wrapping_add($a).wrapping_add(K[$i]).wrapping_add(chunk[G[$i]]);
                $a = $a.rotate_left(R[$i]);
                $a = $a.wrapping_add($b);
            };
        }

        #[inline]
        const fn step1(b: u32, c: u32, d: u32) -> u32 {
            d ^ (b & (c ^ d))
        }
        #[inline]
        const fn step2(b: u32, c: u32, d: u32) -> u32 {
            c ^ (d & (b ^ c))
        }
        #[inline]
        const fn step3(b: u32, c: u32, d: u32) -> u32 {
            b ^ c ^ d
        }
        #[inline]
        const fn step4(b: u32, c: u32, d: u32) -> u32 {
            c ^ (b | !d)
        }

        step!(0, step1);
        step!(16, step2);
        step!(32, step3);
        step!(48, step4);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    #[inline]
    pub fn digest(&self) -> [u8; 16] {
        unsafe { std::mem::transmute(self.state) }
    }
}

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
