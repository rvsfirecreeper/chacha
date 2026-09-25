#![warn(clippy::pedantic)]
mod chacha;
mod poly1305;
pub use chacha::chacha20;
use chacha::chacha20_block;
use poly1305::poly1305;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
type Key = [u8; 32];
type Nonce = [u8; 12];
type State = Zeroizing<[u32; 16]>;
#[derive(Debug)]
pub enum Error {
    CryptoError,   // Apparently your not supposed to tell you what went wrong
    OhGodPleaseNo, // Something has gone Terribly wrong and some invariant has failed.
}
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug))]
struct Poly1305Key([u8; 32]);
impl Poly1305Key {
    /// # Errors
    /// It can't unless an Invariant fails
    fn key_gen(key: Key, nonce: Nonce) -> Result<Self, Error> {
        Ok(Self(
            chacha20_block(key, nonce, 0)?[0..32]
                .try_into()
                .map_err(|_| Error::OhGodPleaseNo)?,
        ))
    }
}
/// # Errors
/// The plaintext is too long, or the universe is broken(Invariants Failed)
pub fn chacha20poly1305_encrypt(
    plaintext: &[u8],
    aad: Option<&[u8]>,
    key: Key,
    nonce: Nonce,
) -> Result<Vec<u8>, Error> {
    let aad = aad.unwrap_or(&[]);
    let ciphertext_raw = chacha20(key, nonce, None, plaintext)?;
    let mut ciphertext_aead = Vec::with_capacity(plaintext.len() + 16);
    ciphertext_aead.extend_from_slice(&ciphertext_raw);
    ciphertext_aead.extend_from_slice(&aead_tag(aad, &ciphertext_raw, key, nonce)?);
    Ok(ciphertext_aead)
}
/// # Errors
/// The ciphertext is too short or fails authentication, or the universe is broken(Invariants Failed)
pub fn chacha20poly1305_decrypt(
    ciphertext: &[u8],
    aad: Option<&[u8]>,
    key: Key,
    nonce: Nonce,
) -> Result<Vec<u8>, Error> {
    let aad = aad.unwrap_or(&[]);
    let split = ciphertext.len().checked_sub(16).ok_or(Error::CryptoError)?;
    let (ciphertext_raw, tag) = ciphertext.split_at(split);
    let expected_tag = aead_tag(aad, ciphertext_raw, key, nonce)?;
    // Constant time comparison, so we don't leak how many bytes of the tag matched
    let diff = tag
        .iter()
        .zip(expected_tag.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if std::hint::black_box(diff) != 0 {
        return Err(Error::CryptoError);
    }
    chacha20(key, nonce, None, ciphertext_raw)
}
fn aead_tag(aad: &[u8], ciphertext: &[u8], key: Key, nonce: Nonce) -> Result<[u8; 16], Error> {
    let tag_key = Poly1305Key::key_gen(key, nonce)?;
    let mut msg = Vec::new();
    msg.extend_from_slice(aad);
    msg.extend(std::iter::repeat_n(0, (16 - msg.len() % 16) % 16));
    msg.extend_from_slice(ciphertext);
    msg.extend(std::iter::repeat_n(0, (16 - msg.len() % 16) % 16));
    msg.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    msg.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305(&tag_key, &msg)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poly1305_key_gen_test() {
        let key = Poly1305Key::key_gen(
            [
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
                0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                0x9c, 0x9d, 0x9e, 0x9f,
            ],
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ],
        )
        .unwrap();
        assert_eq!(
            key.0,
            [
                0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2,
                0x94, 0x71, 0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2,
                0xfd, 0xd1, 0xa6, 0x46
            ]
        );
    }
    #[test]
    fn chacha20poly1305_sunscreen() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."; // I do not condone this statement
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&[0x07, 0x00, 0x00, 0x00]);
        nonce[4..12].copy_from_slice(b"@ABCDEFG");
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let mut aad = [0u8; 12];
        aad[0..4].copy_from_slice(b"PQRS");
        aad[4..12].copy_from_slice(&[0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]);
        assert_eq!(
            chacha20poly1305_encrypt(plaintext, Some(&aad), key, nonce).unwrap(),
            [
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
                0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
                0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
                0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
                0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
                0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
                0xd0, 0x60, 0x06, 0x91,
            ]
        );
    }
    #[test]
    fn chacha20poly1305_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"some header";
        for len in [0u8, 1, 15, 16, 17, 64, 65, 200] {
            let plaintext: Vec<u8> = (0..len).collect();
            let ciphertext = chacha20poly1305_encrypt(&plaintext, Some(aad), key, nonce).unwrap();
            assert_eq!(ciphertext.len(), plaintext.len() + 16);
            let decrypted = chacha20poly1305_decrypt(&ciphertext, Some(aad), key, nonce).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }
    #[test]
    fn chacha20poly1305_rejects_tampering() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"some header";
        let ciphertext =
            chacha20poly1305_encrypt(b"attack at dawn", Some(aad), key, nonce).unwrap();
        // Flipped bit in the ciphertext body
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert!(chacha20poly1305_decrypt(&tampered, Some(aad), key, nonce).is_err());
        // Flipped bit in the tag
        let mut tampered = ciphertext.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(chacha20poly1305_decrypt(&tampered, Some(aad), key, nonce).is_err());
        // Wrong or missing AAD
        assert!(chacha20poly1305_decrypt(&ciphertext, Some(b"other header"), key, nonce).is_err());
        assert!(chacha20poly1305_decrypt(&ciphertext, None, key, nonce).is_err());
        // Too short to even hold a tag
        assert!(chacha20poly1305_decrypt(&ciphertext[..15], Some(aad), key, nonce).is_err());
    }
}
