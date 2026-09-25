use crate::Error;
use crate::Poly1305Key;
use crypto_bigint::{NonZero, U128, U192};
use std::ops::AddAssign;
use zeroize::Zeroizing;
/// # Errors
/// This cannot fail Rust just says it can because reasons. Unless an invariant has gone horribly wrong.
/// If the universe is broken, it will return `Error::OhGodPleaseNo`
pub fn poly1305(key: &Poly1305Key, msg: &[u8]) -> Result<[u8; 16], Error> {
    let mut r = key.0[0..16].try_into().map_err(|_| Error::OhGodPleaseNo)?;
    clamp_r(&mut r);
    let r = Zeroizing::new(U128::from_le_slice(&r));
    let s = Zeroizing::new(U128::from_le_slice(
        (key.0[16..32])
            .try_into()
            .map_err(|_| Error::OhGodPleaseNo)?,
    ));
    let mut a = U192::ZERO;
    let mut chunk_num = Zeroizing::new(U192::ZERO);
    let p: NonZero<U192> = NonZero::from_be_hex("0000000000000003fffffffffffffffffffffffffffffffb");
    for chunk in msg.as_chunks::<16>().0 {
        *chunk_num = U192::from_le_slice_truncated(chunk, 192);
        chunk_num.add_assign(&U192::from_u8(2).wrapping_pow(&U192::from_u8(128)));
        a = a.add_mod(&chunk_num, &p);
        a = a.mul_mod(&U192::from(&*r), &p);
    }
    if !msg.as_chunks::<16>().1.is_empty() {
        *chunk_num = U192::from_le_slice_truncated(msg.as_chunks::<16>().1, 192);
        chunk_num.add_assign(
            &U192::from_u8(2)
                .wrapping_pow(&U192::from_u64((msg.as_chunks::<16>().1.len() * 8) as u64)),
        );
        a = a.add_mod(&chunk_num, &p);
        a = a.mul_mod(&U192::from(&*r), &p);
    }
    a.add_assign(U192::from(&*s));
    (a.to_le_bytes().as_array::<24>())
        .ok_or(Error::OhGodPleaseNo)
        .copied()
        .map(|a| a.first_chunk::<16>().ok_or(Error::OhGodPleaseNo).copied())?
}
fn clamp_r(r: &mut [u8; 16]) {
    r[3] &= 0x0f;
    r[7] &= 0x0f;
    r[11] &= 0x0f;
    r[15] &= 0x0f;
    r[4] &= 0xfc;
    r[8] &= 0xfc;
    r[12] &= 0xfc;
}
#[cfg(test)]
mod tests {
    use crate::{Poly1305Key, poly1305::poly1305};
    #[test]
    fn poly1305_test() {
        let key = Poly1305Key([
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ]);
        let msg = [
            0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20,
            0x46, 0x6f, 0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
            0x20, 0x47, 0x72, 0x6f, 0x75, 0x70,
        ];
        assert_eq!(
            poly1305(&key, &msg).unwrap(),
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9
            ]
        );
    }
}
