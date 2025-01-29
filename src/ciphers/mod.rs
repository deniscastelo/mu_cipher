pub mod three_way_cipher;
pub mod mars_cipher;

pub trait ICipher {
    fn get_block_size(&self) -> usize;
    fn block_decrypt(&self, in_buf: &[u8],len: usize, out_buf: &mut [u8]);
    fn init(&mut self);
}