use ciphers::three_way_cipher::{ThreeWayCipher};
use ciphers::mars_cipher::MarsCipher;
use ciphers::ICipher;


mod ciphers;

fn main() {
    let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    let cipher = MarsCipher::new(&key);

    let mut in_buf = [0u8; 12]; // Bloco de entrada
    let mut out_buf = [0u8; 12]; // Bloco de saída

    cipher.block_decrypt(&in_buf, 13, &mut out_buf);
    println!("Descriptografado: {:?}", out_buf);
}
