use std::ops::Deref;

pub mod altcha;
pub mod anubis;
pub mod capjs;
pub mod cerberus;
pub mod goaway;
pub mod mcaptcha;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(align(8))]
/// A fixed length hex string
pub struct FixedHexString<const N: usize>(pub [u8; N]);

impl<const N: usize> Deref for FixedHexString<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for FixedHexString<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<const N: usize>;
        impl<'de, const N: usize> serde::de::Visitor<'de> for Visitor<N> {
            type Value = FixedHexString<N>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(&format!("a hex string of length {}", N * 2))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<FixedHexString<N>, E>
            where
                E: serde::de::Error,
            {
                let mut res = [0u8; N];
                if v.len() > N * 2 {
                    return Err(serde::de::Error::custom("hex string is too long"));
                }
                for i in 0..N.min(v.len() / 2) {
                    let mut h = v[i * 2];
                    let mut l = v[i * 2 + 1];
                    if h >= b'0' && h <= b'9' {
                        h -= b'0';
                    } else if h >= b'a' && h <= b'f' {
                        h -= b'a' - 10;
                    } else if h >= b'A' && h <= b'F' {
                        h -= b'A' - 10;
                    } else {
                        return Err(serde::de::Error::custom("invalid hex character"));
                    }
                    if l >= b'0' && l <= b'9' {
                        l -= b'0';
                    } else if l >= b'a' && l <= b'f' {
                        l -= b'a' - 10;
                    } else if l >= b'A' && l <= b'F' {
                        l -= b'A' - 10;
                    } else {
                        return Err(serde::de::Error::custom("invalid hex character"));
                    }
                    res[i] = h * 16 + l;
                }
                if let Some(&b) = v.get(v.len() / 2 * 2) {
                    let b = if b >= b'0' && b <= b'9' {
                        b - b'0'
                    } else if b >= b'a' && b <= b'f' {
                        b - b'a' + 10
                    } else if b >= b'A' && b <= b'F' {
                        b - b'A' + 10
                    } else {
                        return Err(serde::de::Error::custom("invalid hex character"));
                    };
                    res[v.len() / 2] = b * 16;
                }
                Ok(FixedHexString(res))
            }
        }

        deserializer.deserialize_bytes(Visitor::<N>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_hex_string() {
        let s = serde_json::from_slice::<FixedHexString<8>>(br#""0123456789abcdef""#).unwrap();
        assert_eq!(s.0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let s = serde_json::from_slice::<FixedHexString<8>>(br#""0123456789abcde""#).unwrap();
        assert_eq!(s.0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xe0]);
        let s = serde_json::from_slice::<FixedHexString<8>>(br#""0123456789abcd""#).unwrap();
        assert_eq!(s.0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0x00]);
        let s = serde_json::from_slice::<FixedHexString<8>>(br#""0123456789abc""#).unwrap();
        assert_eq!(s.0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xc0, 0x00]);
    }
}
