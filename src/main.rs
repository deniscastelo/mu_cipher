use ciphers::three_way_cipher::{ThreeWayCipher};
use ciphers::mars_cipher::MarsCipher;
use ciphers::ICipher;
use ciphers::tea_cipher::TeaCipher;
use ciphers::gost_cipher::GOSTCipher;


mod ciphers;

fn main() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];

    // Inicializar o cifrador
    let cipher = GOSTCipher::new(&key);

    // Bloco de 64 bits (8 bytes) para descriptografar
    let ciphertext: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

    // Descriptografar o bloco
    let decrypted = cipher.decrypt_block(&ciphertext);
    println!("Decrypted: {:02X?}", decrypted);
}
