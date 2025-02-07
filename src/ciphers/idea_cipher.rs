const KEY_SIZE: usize = 16;
const BLOCK_SIZE: usize = 8;
const ROUNDS: usize = 8;
const SUBKEYS_COUNT: usize = 52;

pub struct IDEACipher {
    sub_keys: [u16; SUBKEYS_COUNT],
}

impl IDEACipher {
    pub fn new(key: &[u8]) -> Self {
      let mut cipher = IDEACipher {
        sub_keys: [0u16;SUBKEYS_COUNT],
      };

      cipher.generate_subkeys(&key);
      cipher
    }

    fn generate_subkeys(&mut self, key: &[u8]) {
        let mut key_buffer = [0u16;8];

        for i in 0..8 {
          key_buffer[i] = u16::from_be_bytes([key[2 * i], key[2*i +1]]);
        }

        for i in 0..SUBKEYS_COUNT {
          self.sub_keys[i] = key_buffer[i % 8];
          if i % 8 == 7 {
            let mut carry = 0;
            for j in 0..8 {
                let new_carry = (key_buffer[j] >> 11) & 0x1F;
                key_buffer[j] = ((key_buffer[j] << 5) | carry) & 0xFFFF;
                carry = new_carry;
            }
          }
        }
    }
}
