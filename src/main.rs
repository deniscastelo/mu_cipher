use cast5::cipher::KeyInit;
use ciphers::three_way_cipher::{ThreeWayCipher};
use ciphers::mars_cipher::MarsCipher;
use ciphers::ICipher;
use ciphers::tea_cipher::TeaCipher;
use ciphers::gost_cipher::GOSTCipher;
use ciphers::cast5_cipher::Cast5Cipher;


mod ciphers;

fn main() {
    // Chave de 128 bits (16 bytes)
    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];

    // Inicializar o cifrador
    let cipher = Cast5Cipher::new(&key);

    // Bloco de 64 bits (8 bytes) para criptografar
    let plaintext: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

    // Criptografar o bloco
    let ciphertext = cipher.encrypt_block(&plaintext);
    println!("Ciphertext: {:02X?}", ciphertext);

    // Descriptografar o bloco
    let decrypted = cipher.decrypt_block(&ciphertext);
    println!("Decrypted: {:02X?}", decrypted);

    // Verificar se a descriptografia foi bem-sucedida
    assert_eq!(plaintext, decrypted);
}
