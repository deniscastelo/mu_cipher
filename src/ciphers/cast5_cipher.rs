const BLOCK_SIZE: usize = 8; // 64 bits
const KEY_SIZE: usize = 16; // 128 bits (tamanho máximo da chave para CAST5)
const ROUNDS: usize = 16; // Número de rodadas no CAST5

pub struct Cast5Cipher {
    subkeys: [u32; 32], // 16 rodadas * 2 subchaves por rodada
}

impl Cast5Cipher {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() <= KEY_SIZE, "Key must be 16 bytes or less.");
        let mut cipher = Cast5Cipher { subkeys: [0u32; 32] };
        cipher.expand_key(key);
        cipher
    }

    fn expand_key(&mut self, key: &[u8]) {
        let mut x = [0u32; 4];

        // Converta a chave em um array de u32
        for i in 0..4 {
            x[i] = u32::from_be_bytes([
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ]);
        }

        // Expansão da chave
        let mut z = [0u32; 8];
        for i in 0..8 {
            z[i] = x[i % 4];
        }

        // Geração das subchaves
        for i in 0..16 {
            self.subkeys[2 * i] = z[i % 8];
            self.subkeys[2 * i + 1] = z[(i + 1) % 8];
        }
    }

    fn f(&self, d: u32, km: u32, kr: u8) -> u32 {
        let t = km.wrapping_add(d).rotate_left(kr as u32);
        t
    }

    fn round_function(&self, left: u32, right: u32, round: usize) -> (u32, u32) {
        let km = self.subkeys[2 * round];
        let kr = (self.subkeys[2 * round + 1] & 0x1F) as u8; // kr é um valor de 5 bits

        let f_result = self.f(right, km, kr);
        let new_left = right;
        let new_right = left ^ f_result;

        (new_left, new_right)
    }

    pub fn encrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut left = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut right = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);

        for round in 0..ROUNDS {
            let (new_left, new_right) = self.round_function(left, right, round);
            left = new_left;
            right = new_right;
        }

        let mut output = [0u8; BLOCK_SIZE];
        output[..4].copy_from_slice(&left.to_be_bytes());
        output[4..].copy_from_slice(&right.to_be_bytes());
        output
    }

    pub fn decrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut left = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut right = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);

        for round in (0..ROUNDS).rev() {
            let (new_left, new_right) = self.round_function(left, right, round);
            left = new_left;
            right = new_right;
        }

        let mut output = [0u8; BLOCK_SIZE];
        output[..4].copy_from_slice(&left.to_be_bytes());
        output[4..].copy_from_slice(&right.to_be_bytes());
        output
    }

    pub fn block_encrypt(&self, in_buf: &[u8], out_buf: &mut [u8]) {
        assert_eq!(in_buf.len() % BLOCK_SIZE, 0, "Input length must be a multiple of block size.");
        assert_eq!(out_buf.len(), in_buf.len(), "Output buffer must have the same length as input buffer.");

        for i in (0..in_buf.len()).step_by(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&in_buf[i..i + BLOCK_SIZE]);
            let encrypted_block = self.encrypt_block(&block);
            out_buf[i..i + BLOCK_SIZE].copy_from_slice(&encrypted_block);
        }
    }

    pub fn block_decrypt(&self, in_buf: &[u8], out_buf: &mut [u8]) {
        assert_eq!(in_buf.len() % BLOCK_SIZE, 0, "Input length must be a multiple of block size.");
        assert_eq!(out_buf.len(), in_buf.len(), "Output buffer must have the same length as input buffer.");

        for i in (0..in_buf.len()).step_by(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&in_buf[i..i + BLOCK_SIZE]);
            let decrypted_block = self.decrypt_block(&block);
            out_buf[i..i + BLOCK_SIZE].copy_from_slice(&decrypted_block);
        }
    }
}