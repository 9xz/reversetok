// GB/T 32905-2016 SM3, matching tools/sm3.py and the native VM implementation.

const IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

#[inline]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

pub fn sm3(data: &[u8]) -> [u8; 32] {
    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = IV;
    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 68];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let offset = i * 4;
            *word = u32::from_be_bytes(block[offset..offset + 4].try_into().unwrap());
        }
        for j in 16..68 {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
                ^ w[j - 13].rotate_left(7)
                ^ w[j - 6];
        }
        let mut derived = [0u32; 64];
        for j in 0..64 {
            derived[j] = w[j] ^ w[j + 4];
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for j in 0..64 {
            let constant: u32 = if j < 16 { 0x79cc_4519 } else { 0x7a87_9d8a };
            let ss1 = (a
                .rotate_left(12)
                .wrapping_add(e)
                .wrapping_add(constant.rotate_left(j as u32)))
            .rotate_left(7);
            let ss2 = ss1 ^ a.rotate_left(12);
            let (ff, gg) = if j < 16 {
                (a ^ b ^ c, e ^ f ^ g)
            } else {
                ((a & b) | (a & c) | (b & c), (e & f) | ((!e) & g))
            };
            let tt1 = ff
                .wrapping_add(d)
                .wrapping_add(ss2)
                .wrapping_add(derived[j]);
            let tt2 = gg.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
            d = c;
            c = b.rotate_left(9);
            b = a;
            a = tt1;
            h = g;
            g = f.rotate_left(19);
            f = e;
            e = p0(tt2);
        }
        state = [
            state[0] ^ a,
            state[1] ^ b,
            state[2] ^ c,
            state[3] ^ d,
            state[4] ^ e,
            state[5] ^ f,
            state[6] ^ g,
            state[7] ^ h,
        ];
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sm3;

    #[test]
    fn standard_vectors() {
        assert_eq!(
            hex::encode(sm3(b"abc")),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
        assert_eq!(
            hex::encode(sm3(b"abcd".repeat(16).as_slice())),
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        );
    }
}
