use super::ICipher;

pub struct TeaCipher {
    key: [u32; 4],
}

impl TeaCipher {
    pub fn new(key: &[u8]) -> Self {
        let mut key_u32 = [0u32; 4];

        for i in 0..4 {
            key_u32[i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        Self { key: key_u32 }
    }

    pub fn encrypt_block(&self, data: &mut [u32; 2]) {
        let mut v0 = data[0];
        let mut v1 = data[1];
        let mut sum = 0u32;

        for _ in 0..32 {
            sum = sum.wrapping_add(0x9E3779B9);
            v0 = v0.wrapping_add(
                ((v1 << 4).wrapping_add(self.key[0]))
                    ^ (v1.wrapping_add(sum))
                    ^ ((v1 >> 5).wrapping_add(self.key[1])),
            );
            v1 = v1.wrapping_add(
                ((v0 << 4).wrapping_add(self.key[2]))
                    ^ (v0.wrapping_add(sum))
                    ^ ((v0 >> 5).wrapping_add(self.key[3])),
            );
        }

        data[0] = v0;
        data[1] = v1;
    }

    pub fn decrypt_block(&self, in_buf: &[u32; 2], out_buf: &mut [u32; 2]) {
        let mut v0 = in_buf[0];
        let mut v1 = in_buf[1];
        let mut sum = 0xC6EF3720u32;

        for _ in 0..32 {
            v1 = v1.wrapping_sub(
                ((v0 << 4).wrapping_add(self.key[2]))
                    ^ (v0.wrapping_add(sum))
                    ^ ((v0 >> 5).wrapping_add(self.key[3])),
            );
            v0 = v0.wrapping_sub(
                ((v1 << 4).wrapping_add(self.key[0]))
                    ^ (v1.wrapping_add(sum))
                    ^ ((v1 >> 5).wrapping_add(self.key[1])),
            );
            sum = sum.wrapping_sub(0x9E3779B9);
        }

        out_buf[0] = v0;
        out_buf[1] = v1;
    }
}

impl ICipher for TeaCipher {
    fn get_block_size(&self) -> usize {
        8
    }

    fn block_decrypt(&self, in_buf: &[u8], len: usize, out_buf: &mut [u8]) {
        let block_size = self.get_block_size();

        for i in (0..in_buf.len()).step_by(block_size) {
            let mut block = bytes_to_u32_array(&in_buf[i..i + block_size]);
            let mut block_out = [0u32; 2];

            self.decrypt_block(&block, &mut block_out);

            let bytes = u32_array_to_bytes(block_out);

            let _ = &out_buf[i..i + block_size].copy_from_slice(&bytes);
        }
    }
}

fn bytes_to_u32_array(bytes: &[u8]) -> [u32; 2] {
    let mut block = [0u32; 2];
    for i in 0..2 {
        block[i] = u32::from_le_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
    block
}

fn u32_array_to_bytes(block: [u32; 2]) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    for i in 0..2 {
        let chunk = block[i].to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&chunk);
    }
    bytes
}
