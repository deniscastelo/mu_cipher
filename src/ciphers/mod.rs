pub mod three_way_cipher;
pub mod mars_cipher;
pub mod tea_cipher;
pub mod gost_cipher;
pub mod cast5_cipher;
pub mod idea_cipher;

pub trait ICipher {
    fn get_block_size(&self) -> usize;
    fn block_decrypt(&self, in_buf: &[u8],len: usize, out_buf: &mut [u8]);
}