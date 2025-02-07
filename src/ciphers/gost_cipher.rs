use super::ICipher;

const BLOCK_SIZE: usize = 8; // 64 bits
const KEY_SIZE: usize = 32; // 256 bits
const ROUNDS: usize = 32;

// S-box padrão (exemplo)
const S_BOX: [[u8; 16]; 8] = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
];

pub struct GOSTCipher {
    keys: [u32; 8],
}

impl GOSTCipher {
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let mut keys = [0u32; 8];
        for i in 0..8 {
            keys[i] =
                u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        GOSTCipher { keys }
    }

    fn s_box_substitution(&self, value: u32) -> u32 {
        let mut result = 0;
        for i in 0..8 {
            let nibble = (value >> (4 * i)) & 0xF;
            let substituted = S_BOX[i][nibble as usize] as u32;
            result |= substituted << (4 * i);
        }
        result
    }

    fn round_function(&self, data: u32, key: u32) -> u32 {
        let temp = data.wrapping_add(key);
        let substituted = self.s_box_substitution(temp);
        substituted.rotate_left(11)
    }

    pub fn decrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut left = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let mut right = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);

        for i in (0..ROUNDS).rev() {
            let key = self.keys[i % 8];
            let temp = left ^ self.round_function(right, key);
            if i > 0 {
                left = right;
                right = temp;
            } else {
                left = temp;
            }
        }

        let mut output = [0u8; BLOCK_SIZE];
        output[..4].copy_from_slice(&left.to_le_bytes());
        output[4..].copy_from_slice(&right.to_le_bytes());
        output
    }

    pub fn block_decrypt(&self, in_buf: &[u8], out_buf: &mut [u8]) {
        assert_eq!(
            in_buf.len() % BLOCK_SIZE,
            0,
            "Input length must be a multiple of block size."
        );
        assert_eq!(
            out_buf.len(),
            in_buf.len(),
            "Output buffer must have the same length as input buffer."
        );

        for i in (0..in_buf.len()).step_by(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&in_buf[i..i + BLOCK_SIZE]);
            let decrypted_block = self.decrypt_block(&block);
            out_buf[i..i + BLOCK_SIZE].copy_from_slice(&decrypted_block);
        }
    }
}

impl ICipher for GOSTCipher {
    fn get_block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn block_decrypt(&self, in_buf: &[u8],len: usize, out_buf: &mut [u8]) {
        
        let block_size = self.get_block_size();

        for i in (0..in_buf.len()).step_by(block_size) {
          self.block_decrypt(in_buf, out_buf);
        }

    }
    
}