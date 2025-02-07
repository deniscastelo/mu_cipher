use std::convert::TryInto;

use super::ICipher;

pub struct ThreeWayCipher {
    m_k: [u32; 3],
    m_rounds: usize,
}

impl ThreeWayCipher {
    const START_E: u32 = 0x0b0b;
    const START_D: u32 = 0xb1b1;
    const BLOCK_SIZE: usize = 12;

    pub fn new(key: &[u8]) -> Self {
        //assert_eq!(key.len(), 12, "Key must be 12 bytes long.");

        let mut m_k = [0u32; 3];
        for i in 0..3 {
            m_k[i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
        }

        let mut a01 = m_k[0];
        let mut a02 = m_k[1];
        let mut a03 = m_k[2];

        // Aplicar transformações de chave para descriptografia
        Self::theta(&mut a01, &mut a02, &mut a03);

        m_k[0] = a01;
        m_k[1] = a02;
        m_k[2] = a03;

        let mut a01 = m_k[0];
        let mut a02 = m_k[1];
        let mut a03 = m_k[2];

        Self::mu(&mut a01, &mut a02, &mut a03);
        m_k[0] = m_k[0].swap_bytes();
        m_k[1] = m_k[1].swap_bytes();
        m_k[2] = m_k[2].swap_bytes();

        ThreeWayCipher { m_k, m_rounds: 11 }
    }

    fn reverse_bits(a: u32) -> u32 {
        let mut a = a;
        a = ((a & 0xAAAAAAAA) >> 1) | ((a & 0x55555555) << 1);
        a = ((a & 0xCCCCCCCC) >> 2) | ((a & 0x33333333) << 2);
        ((a & 0xF0F0F0F0) >> 4) | ((a & 0x0F0F0F0F) << 4)
    }

    fn rotate_left(x: u32, n: u32) -> u32 {
        x.rotate_left(n)
    }

    fn rotl_constant(x: u32, r: u32) -> u32 {
        Self::rotate_left(x, r)
    }

    fn theta(a0: &mut u32, a1: &mut u32, a2: &mut u32) {
        let c = *a0 ^ *a1 ^ *a2;
        let c = Self::rotl_constant(c, 16) ^ Self::rotl_constant(c, 8);
        let b0 = (*a0 << 24) ^ (*a2 >> 8) ^ (*a1 << 8) ^ (*a0 >> 24);
        let b1 = (*a1 << 24) ^ (*a0 >> 8) ^ (*a2 << 8) ^ (*a1 >> 24);
        *a0 ^= c ^ b0;
        *a1 ^= c ^ b1;
        *a2 ^= c ^ (b0 >> 16) ^ (b1 << 16);
    }

    fn mu(a0: &mut u32, a1: &mut u32, a2: &mut u32) {
        *a1 = Self::reverse_bits(*a1);
        let t = Self::reverse_bits(*a0);
        *a0 = Self::reverse_bits(*a2);
        *a2 = t;
    }

    fn pi_gamma_pi(a0: &mut u32, a1: &mut u32, a2: &mut u32) {
        let b2 = Self::rotl_constant(*a2, 1);
        let b0 = Self::rotl_constant(*a0, 22);
        *a0 = Self::rotl_constant(b0 ^ (*a1 | (!b2)), 1);
        *a2 = Self::rotl_constant(b2 ^ (b0 | (!*a1)), 22);
        *a1 ^= b2 | (!b0);
    }

    fn rho(a0: &mut u32, a1: &mut u32, a2: &mut u32) {
        Self::theta(a0, a1, a2);
        Self::pi_gamma_pi(a0, a1, a2);
    }

    fn read_u32_le(buffer: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap())
    }

    fn write_u32_le(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn decrypt_block(&self, in_block: &[u8], out_block: &mut [u8]) {
        assert_eq!(
            in_block.len(),
            Self::BLOCK_SIZE,
            "Input block must be 12 bytes."
        );
        assert_eq!(
            out_block.len(),
            Self::BLOCK_SIZE,
            "Output block must be 12 bytes."
        );

        let mut a0 = Self::read_u32_le(in_block, 0);
        let mut a1 = Self::read_u32_le(in_block, 4);
        let mut a2 = Self::read_u32_le(in_block, 8);

        let mut rc = Self::START_D;

        Self::mu(&mut a0, &mut a1, &mut a2);

        for _ in 0..self.m_rounds {
            a0 ^= self.m_k[0] ^ (rc << 16);
            a1 ^= self.m_k[1];
            a2 ^= self.m_k[2] ^ rc;
            Self::rho(&mut a0, &mut a1, &mut a2);

            rc <<= 1;
            if (rc & 0x10000) != 0 {
                rc ^= 0x11011;
            }
        }

        a0 ^= self.m_k[0] ^ (rc << 16);
        a1 ^= self.m_k[1];
        a2 ^= self.m_k[2] ^ rc;
        Self::theta(&mut a0, &mut a1, &mut a2);
        Self::mu(&mut a0, &mut a1, &mut a2);

        Self::write_u32_le(out_block, 0, a0);
        Self::write_u32_le(out_block, 4, a1);
        Self::write_u32_le(out_block, 8, a2);
    }

    pub fn block_decrypt(&self, in_buf: &[u8], out_buf: &mut [u8]) {
        assert_eq!(
            in_buf.len() % Self::BLOCK_SIZE,
            0,
            "Input length must be a multiple of block size."
        );
        assert_eq!(
            out_buf.len(),
            in_buf.len(),
            "Output buffer must have the same length as input buffer."
        );

        for i in (0..in_buf.len()).step_by(Self::BLOCK_SIZE) {
            self.decrypt_block(
                &in_buf[i..i + Self::BLOCK_SIZE],
                &mut out_buf[i..i + Self::BLOCK_SIZE],
            );
        }
    }
}

impl ICipher for ThreeWayCipher {
    fn get_block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn block_decrypt(&self, in_buf: &[u8], len: usize, out_buf: &mut [u8]) {
        self.block_decrypt(&in_buf[..len], out_buf);
    }
}
