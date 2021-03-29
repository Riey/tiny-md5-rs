#[repr(C)]
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
            ($formulation:ident, $a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $g:expr, $r:expr) => {
                $a = $formulation($b, $c, $d)
                    .wrapping_add($a)
                    .wrapping_add($k)
                    .wrapping_add(chunk[$g])
                    .rotate_left($r)
                    .wrapping_add($b);
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

        step!(step1, a, b, c, d, 0xd76aa478, 0, 7);
        step!(step1, d, a, b, c, 0xe8c7b756, 1, 12);
        step!(step1, c, d, a, b, 0x242070db, 2, 17);
        step!(step1, b, c, d, a, 0xc1bdceee, 3, 22);
        step!(step1, a, b, c, d, 0xf57c0faf, 4, 7);
        step!(step1, d, a, b, c, 0x4787c62a, 5, 12);
        step!(step1, c, d, a, b, 0xa8304613, 6, 17);
        step!(step1, b, c, d, a, 0xfd469501, 7, 22);
        step!(step1, a, b, c, d, 0x698098d8, 8, 7);
        step!(step1, d, a, b, c, 0x8b44f7af, 9, 12);
        step!(step1, c, d, a, b, 0xffff5bb1, 10, 17);
        step!(step1, b, c, d, a, 0x895cd7be, 11, 22);
        step!(step1, a, b, c, d, 0x6b901122, 12, 7);
        step!(step1, d, a, b, c, 0xfd987193, 13, 12);
        step!(step1, c, d, a, b, 0xa679438e, 14, 17);
        step!(step1, b, c, d, a, 0x49b40821, 15, 22);

        step!(step2, a, b, c, d, 0xf61e2562, 1, 5);
        step!(step2, d, a, b, c, 0xc040b340, 6, 9);
        step!(step2, c, d, a, b, 0x265e5a51, 11, 14);
        step!(step2, b, c, d, a, 0xe9b6c7aa, 0, 20);
        step!(step2, a, b, c, d, 0xd62f105d, 5, 5);
        step!(step2, d, a, b, c, 0x02441453, 10, 9);
        step!(step2, c, d, a, b, 0xd8a1e681, 15, 14);
        step!(step2, b, c, d, a, 0xe7d3fbc8, 4, 20);
        step!(step2, a, b, c, d, 0x21e1cde6, 9, 5);
        step!(step2, d, a, b, c, 0xc33707d6, 14, 9);
        step!(step2, c, d, a, b, 0xf4d50d87, 3, 14);
        step!(step2, b, c, d, a, 0x455a14ed, 8, 20);
        step!(step2, a, b, c, d, 0xa9e3e905, 13, 5);
        step!(step2, d, a, b, c, 0xfcefa3f8, 2, 9);
        step!(step2, c, d, a, b, 0x676f02d9, 7, 14);
        step!(step2, b, c, d, a, 0x8d2a4c8a, 12, 20);

        step!(step3, a, b, c, d, 0xfffa3942, 5, 4);
        step!(step3, d, a, b, c, 0x8771f681, 8, 11);
        step!(step3, c, d, a, b, 0x6d9d6122, 11, 16);
        step!(step3, b, c, d, a, 0xfde5380c, 14, 23);
        step!(step3, a, b, c, d, 0xa4beea44, 1, 4);
        step!(step3, d, a, b, c, 0x4bdecfa9, 4, 11);
        step!(step3, c, d, a, b, 0xf6bb4b60, 7, 16);
        step!(step3, b, c, d, a, 0xbebfbc70, 10, 23);
        step!(step3, a, b, c, d, 0x289b7ec6, 13, 4);
        step!(step3, d, a, b, c, 0xeaa127fa, 0, 11);
        step!(step3, c, d, a, b, 0xd4ef3085, 3, 16);
        step!(step3, b, c, d, a, 0x04881d05, 6, 23);
        step!(step3, a, b, c, d, 0xd9d4d039, 9, 4);
        step!(step3, d, a, b, c, 0xe6db99e5, 12, 11);
        step!(step3, c, d, a, b, 0x1fa27cf8, 15, 16);
        step!(step3, b, c, d, a, 0xc4ac5665, 2, 23);

        step!(step4, a, b, c, d, 0xf4292244, 0, 6);
        step!(step4, d, a, b, c, 0x432aff97, 7, 10);
        step!(step4, c, d, a, b, 0xab9423a7, 14, 15);
        step!(step4, b, c, d, a, 0xfc93a039, 5, 21);
        step!(step4, a, b, c, d, 0x655b59c3, 12, 6);
        step!(step4, d, a, b, c, 0x8f0ccc92, 3, 10);
        step!(step4, c, d, a, b, 0xffeff47d, 10, 15);
        step!(step4, b, c, d, a, 0x85845dd1, 1, 21);
        step!(step4, a, b, c, d, 0x6fa87e4f, 8, 6);
        step!(step4, d, a, b, c, 0xfe2ce6e0, 15, 10);
        step!(step4, c, d, a, b, 0xa3014314, 6, 15);
        step!(step4, b, c, d, a, 0x4e0811a1, 13, 21);
        step!(step4, a, b, c, d, 0xf7537e82, 4, 6);
        step!(step4, d, a, b, c, 0xbd3af235, 11, 10);
        step!(step4, c, d, a, b, 0x2ad7d2bb, 2, 15);
        step!(step4, b, c, d, a, 0xeb86d391, 9, 21);

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
