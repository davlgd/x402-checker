//! Base58 as Solana spells its public keys and signatures: the Bitcoin alphabet, leading `1`s standing for leading
//! zero bytes. Case-sensitive, never normalised.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn digit(c: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|p| u32::try_from(p).ok())
}

/// The bytes a base58 string encodes, `None` when a character is outside the alphabet or the string is empty.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return None;
    }
    let zeros = text.bytes().take_while(|&b| b == b'1').count();
    let mut number: Vec<u32> = Vec::new(); // little-endian base 256
    for c in text.bytes() {
        let mut carry = digit(c)?;
        for limb in &mut number {
            let value = *limb * 58 + carry;
            *limb = value & 0xff;
            carry = value >> 8;
        }
        while carry > 0 {
            number.push(carry & 0xff);
            carry >>= 8;
        }
    }
    let mut bytes = vec![0u8; zeros];
    bytes.extend(number.iter().rev().map(|&b| u8::try_from(b).unwrap_or(0)));
    Some(bytes)
}

/// Whether `text` is the base58 form of exactly 32 bytes: a Solana public key, a mint, a blockhash.
pub fn is_public_key(text: &str) -> bool {
    decode(text).is_some_and(|b| b.len() == 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_spec_examples_to_32_bytes() {
        for key in [
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4",
            "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd",
            "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k",
        ] {
            assert!(is_public_key(key), "{key}");
        }
    }

    #[test]
    fn leading_ones_are_zero_bytes_and_the_alphabet_is_strict() {
        assert_eq!(decode("11111111111111111111111111111111"), Some(vec![0u8; 32]));
        assert_eq!(decode("111"), Some(vec![0u8; 3]));
        assert_eq!(decode("0OIl"), None);
        assert_eq!(decode(""), None);
        assert!(!is_public_key("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v1"));
        // known vector: "2NEpo7TZRRrLZSi2U" is "Hello World!"
        assert_eq!(decode("2NEpo7TZRRrLZSi2U"), Some(b"Hello World!".to_vec()));
    }
}
