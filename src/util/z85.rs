// whirlpool-client-rs
// Copyright (C) 2022  Straylight <straylight_orbit@protonmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! This is a verbatim port of the Z85 (Ascii85) implementation used by Samourai.
//! Unlike Base64, Z85 implementations seem to differ wildly in terms of padding etc.

const DECODERS: &[u8] = &[
    0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00, 0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47,
    0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00,
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00,
];

const ENCODERS: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z', '.', '-', ':', '+', '=', '^', '!', '/', '*', '?', '&', '<', '>', '(',
    ')', '[', ']', '{', '}', '@', '%', '$', '#',
];

const PADDING: char = '#';

/// Decodes a Z85 string into a byte vector. Returns `None` if the string is invalid Z85.
pub fn decode<T: AsRef<str>>(s: T) -> Option<Vec<u8>> {
    let s = s.as_ref();
    let remainder = s.len() % 5;
    let padding = 5 - if remainder == 0 { 5 } else { remainder };
    let mut ret = vec![0_u8; ((s.len() + padding) * 4) / 5 - padding];
    let mut index = 0_usize;
    let mut value = 0_u32;
    for (i, c) in s
        .chars()
        .chain(std::iter::repeat(PADDING).take(padding))
        .enumerate()
    {
        if !ENCODERS.contains(&c) {
            return None;
        }
        let code = c as usize - 32;
        value = value * 85 + *DECODERS.get(code)? as u32;
        if (i + 1) % 5 == 0 {
            let mut div = 256 * 256 * 256;
            while div >= 1 {
                if index < ret.len() {
                    ret[index] = ((value / div) % 256) as u8;
                    index += 1;
                }
                div = div / 256;
            }
            value = 0;
        }
    }

    Some(ret)
}

/// Encodes a byte slice into a Z85 string.
pub fn encode<T: AsRef<[u8]>>(bytes: T) -> String {
    let bytes = bytes.as_ref();
    let remainder = bytes.len() % 4;
    let padding = if remainder > 0 { 4 - remainder } else { 0 };
    let mut ret = String::with_capacity((bytes.len() * 5) / 4);
    let mut value = 0_u32;

    for i in 0..(bytes.len() + padding) {
        let is_padding = i >= bytes.len();
        value = value * 256
            + if is_padding {
                0
            } else {
                (bytes[i] & 0xFF) as u32
            };

        if (i + 1) % 4 == 0 {
            let mut div: u32 = 85 * 85 * 85 * 85;

            for j in (1..=5).rev() {
                if !is_padding || j > padding {
                    let code = (value / div) % 85;
                    ret.push(ENCODERS[code as usize]);
                }
                div = div / 85;
            }
            value = 0;
        }
    }

    ret
}

#[cfg(test)]
mod test {
    use super::{decode, encode};

    #[test]
    fn encode_decode() {
        let text = "A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution. Digital signatures provide part of the solution, but the main benefits are lost if a trusted third party is still required to prevent double-spending. We propose a solution to the double-spending problem using a peer-to-peer network. The network timestamps transactions by hashing them into an ongoing chain of hash-based proof-of-work, forming a record that cannot be changed without redoing the proof-of-work. The longest chain not only serves as proof of the sequence of events witnessed, but proof that it came from the largest pool of CPU power. As long as a majority of CPU power is controlled by nodes that are not cooperating to attack the network, they'll generate the longest chain and outpace attackers. The network itself requires minimal structure. Messages are broadcast on a best effort basis, and nodes can leave and rejoin the network at will, accepting the longest proof-of-work chain as proof of what happened while they were gone.1234567890-_)({(@";
        let bytes = text.as_bytes();

        let encoded = encode(bytes);
        assert_eq!(encoded, "k{gb?A+f6jaAg[6AXhxKePtojAV/KpA=U@kzxJ>faz2w2v@#:fzFrP6v{%B(aA}:Dy?aU%y&13laA8dlx(mG8Aaa3ewO#QhaARJAvR3W6wO#Pjwnc6}v@#KjazbUjz6i+mwGU@2A==NHBz&pgzF%SgwPw]qx([3bB-X:sz!T94aARpqz/]YaayMy8x(mu%v}/v/azC.mBzk&tBzkVhe*9L@xk8D@y-)!kxkRd1B-I5maAhvtC4>F#aAg+fBrCHlaARpdaAIEqB-.tozy=]tB-X:FxK@r6vqfQ4vR6B*w[=vdayPq4az+$qBrCpfayMymA=(CBwN({9xLzG$aAg+fBA]0yB0bKCx(4PdA+flkx(W=}aARJAAb]JkwO#Pjwn=Q1y?khtAaJ]$x(mMoaxJa%Ab](oz/YFjvixSfy&%&lz/cXtzY<dnwGUJ4BZ/e#ePU(xzE^E0xcqelz^)J]z6i$xx(mMavixJ2wPxwAz.k{twPw]hwPScmA+^oIra]?=zE){lz/PRoBzkP6B97&cAc0dzA:-<bvpKy[z/fRsvTf8fvrl9@zF78lxK#36x(n3hayPdgz/fiax(mMav}Yp+zxJ>fazth8xF0X4B7F(8Ab](nw?v}keQ8bNyB*Puz/PYezF782aAz46z/PwhBzb98ay!?$zF%RtvR3V(xKL^>wN({cx([3bB-X:DwN]Z[zF78lxK@r9A=k(dePkkMCw?Iqe*abbwGU/czF9K4BrC7bvqfQ4zF%Rtz/fxpaAIamC4C.qvriMgA=k(daA7<mBzbkdB7GulwO#0?aA7<mwP?T5BAnNGx([l7B8$]6efFzABrCKyz/okgBzb98azC{uv{%j=azbUjz6i}lwGU!$A+w%8BrCKvz!{Lmw/%DqruMm0Cv+!Eavg5>y&si7ayPslvixz}yhXcbBA]0Ew/%DqruMm0Cv+!qx(+zbz/fVqz!%l3wftubaz#adwPF#oxKM09vrb{4zF%Rtv@Dp8wPzj3x(mMaBz&pgBAy@3yAN.jwGU(4BA.UzyB*PIxK#Dpy?$kbwO#71vru66Bzbkdy&si7wPI@ov}Yp+zxJw9wft/kBz$U#wGUA6BywV{wPz&Aaxi2=az$+jCw?IqazC}swO+%3A+flkx(W^aaz>?gx(do{aAITBBZ]JoA+c<Co>wx!vp%d)ayPq4ayYwfvpS>RB95KyzxJvgvR6R5az2d%z/P}xvQTs(B1wCxzE:(cz!9B2ay!?$az+Q$C4z!8zE:(gwOMc$zxK4mwGU(4BA.UzyAN5caA}Koy+cYqv}f7?BzkS9aARpdaz+$lxjVdaaAhvtz!pOtw?wjBA+=!cxKLQ)ayPslAb](nw/#27aA}HcBrCm9AbYxawN({cxLzo]aARpdC{4rxA+cwaz/fbsf!$Kwh8WxMiwr3(djxJ>kM");

        let decoded = decode(encoded).unwrap();

        assert_eq!(&decoded, bytes);
    }
}
