#![warn(clippy::pedantic)]
mod chacha;
mod poly1305;
use chacha::block;
pub use chacha::chacha20;
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
            block(key, nonce, 0)?[0..32]
                .try_into()
                .map_err(|_| Error::OhGodPleaseNo)?,
        ))
    }
}
fn chacha20poly1305() {}
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
}
