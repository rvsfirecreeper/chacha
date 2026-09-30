use crate::chacha::inner_block;
use crate::{Error, chacha20};
use crate::{Key, Nonce, State};
use zeroize::Zeroizing;
fn h_initialize_state(key: Key, nonce: Nonce<16>) -> Result<State, Error> {
    let mut ikey = Zeroizing::new([0u32; 8]); // Intermediate key representation
    for (i, val) in ikey.iter_mut().enumerate() {
        *val = u32::from_le_bytes(
            key[(i * 4)..(4 + (i * 4))]
                .try_into()
                .map_err(|_| Error::OhGodPleaseNo)?,
        );
    }
    let mut inonce = [0u32; 4]; // Intermediate nonce representation
    for (i, val) in inonce.iter_mut().enumerate() {
        *val = u32::from_le_bytes(
            nonce[(i * 4)..(4 + (i * 4))]
                .try_into()
                .map_err(|_| Error::OhGodPleaseNo)?,
        );
    }
    Ok(Zeroizing::new([
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        ikey[0],
        ikey[1],
        ikey[2],
        ikey[3],
        ikey[4],
        ikey[5],
        ikey[6],
        ikey[7],
        inonce[0],
        inonce[1],
        inonce[2],
        inonce[3],
    ]))
}
pub fn hchacha20(key: Key, nonce: Nonce<16>) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut serialized = Zeroizing::new([0u8; 32]);
    let mut state = h_initialize_state(key, nonce)?;
    // HChaCha20 does not add the initial state back in, unlike the ChaCha20 block function
    inner_block(&mut state);
    for (i, val) in state
        .first_chunk::<4>()
        .ok_or(Error::OhGodPleaseNo)?
        .iter()
        .enumerate()
    {
        serialized[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
    }
    for (i, val) in state
        .last_chunk::<4>()
        .ok_or(Error::OhGodPleaseNo)?
        .iter()
        .enumerate()
    {
        serialized[i * 4 + 16..i * 4 + 20].copy_from_slice(&val.to_le_bytes());
    }
    Ok(serialized)
}
/// # Errors
/// Can error out due to too long plaintext OR invariants failing terribly.
pub fn xchacha20(
    key: Key,
    nonce: Nonce<24>,
    plaintext: &[u8],
    counter: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let subkey = hchacha20(
        key,
        nonce[0..16].try_into().map_err(|_| Error::OhGodPleaseNo)?,
    )?;
    let mut functionalnonce = [0u8; 12];
    functionalnonce[4..12].copy_from_slice(&nonce[16..24]);
    chacha20(&subkey, functionalnonce, counter, plaintext)
}
#[cfg(test)]
mod tests {
    use crate::xchacha::hchacha20;
    #[test]

    fn hchacha20_test() {
        assert_eq!(
            *hchacha20(
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                ],
                [
                    00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31,
                    0x41, 0x59, 0x27
                ]
            )
            .unwrap(),
            [
                0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
                0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
                0x26, 0xd3, 0xec, 0xdc,
            ],
        );
    }
}
