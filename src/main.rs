use ciphers::three_way_cipher::{ThreeWayCipher};
use ciphers::mars_cipher::MarsCipher;
use ciphers::ICipher;
use ciphers::tea_cipher::TeaCipher;


mod ciphers;

fn main() {
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
    let cipher = TeaCipher::new(&key);

    let mut in_buf = [0u8; 16]; // Bloco de entrada
    let mut out_buf = [0u8; 16]; // Bloco de saída

    cipher.block_decrypt(&in_buf, 13, &mut out_buf);
    println!("Descriptografado: {:?}", out_buf);
}
