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

//! Rudimentary subset of the BIP47 standard.

use bitcoin::base58;
use bitcoin::bip32::{self, ChainCode, ChildNumber, ExtendedPubKey};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{secp256k1, PrivateKey, PublicKey};

const PAYMENT_CODE_BIN_LENGTH: usize = 80;
const LETTER_P: u8 = 0x47;

#[derive(Debug)]
pub struct PaymentCode(pub ExtendedPubKey);

impl PaymentCode {
    pub fn try_from_str(value: &str) -> Result<Self, Error> {
        let payment_code = base58::decode_check(value).map_err(Error::Base58)?;

        if payment_code.first() != Some(&LETTER_P) {
            return Err(Error::Format("Incorrect version bytes"));
        }

        PaymentCode::try_from_bytes(&payment_code[1..])
    }

    fn try_from_bytes(payment_code: &[u8]) -> Result<Self, Error> {
        if payment_code.len() != PAYMENT_CODE_BIN_LENGTH {
            return Err(Error::Format("Incorrect binary length"));
        }

        let public_key = PublicKey::from_slice(&payment_code[2..35])?.inner;
        let chain_code = ChainCode::from(
            &payment_code[35..67]
                .try_into()
                .map_err(|_| Error::Format("Unable to extract chaincode"))?,
        );

        let network = bitcoin::Network::Bitcoin;

        let xpub = ExtendedPubKey {
            network,
            chain_code,
            child_number: ChildNumber::Normal { index: 0 },
            depth: 3,
            parent_fingerprint: bip32::Fingerprint::default(),
            public_key,
        };

        Ok(Self(xpub))
    }

    pub fn notification_pubkey(&self) -> Result<PublicKey, Error> {
        let curve = Secp256k1::new();
        let child = self.0.ckd_pub(&curve, ChildNumber::from_normal_idx(0)?);
        let key = child?.to_pub();

        Ok(key)
    }
}

pub fn blinding_factor(
    sk: &PrivateKey,
    pk: &PublicKey,
    utxo: &bitcoin::OutPoint,
) -> Result<[u8; 64], secp256k1::Error> {
    let pk = pk.inner.mul_tweak(&Secp256k1::new(), &sk.inner.into())?;

    let mut encoded_utxo = Vec::with_capacity(36);
    encoded_utxo.extend_from_slice(utxo.txid.as_byte_array().as_slice());
    encoded_utxo.extend_from_slice(&u32_to_le_bytes(utxo.vout));

    use bitcoin::hashes::{self, sha512, HashEngine, Hmac};
    let mut hmac = hashes::hmac::HmacEngine::<sha512::Hash>::new(&encoded_utxo);
    hmac.input(&pk.serialize()[1..]);
    let hash = Hmac::<sha512::Hash>::from_engine(hmac);

    Ok(hash.to_byte_array().to_owned())
}

fn u32_to_le_bytes(x: u32) -> [u8; 4] {
    let b1: u8 = (x & 0xff) as u8;
    let b2: u8 = ((x >> 8) & 0xff) as u8;
    let b3: u8 = ((x >> 16) & 0xff) as u8;
    let b4: u8 = ((x >> 24) & 0xff) as u8;
    [b1, b2, b3, b4]
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    Format(&'static str),
    Base58(base58::Error),
    Bip32(bip32::Error),
    Ecdsa(secp256k1::Error),
    Key(bitcoin::key::Error),
}

impl From<bip32::Error> for Error {
    fn from(error: bip32::Error) -> Self {
        Error::Bip32(error)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(error: secp256k1::Error) -> Self {
        Error::Ecdsa(error)
    }
}

impl From<bitcoin::key::Error> for Error {
    fn from(error: bitcoin::key::Error) -> Self {
        Error::Key(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Format(inner) => write!(f, "Format: {}", inner),
            Error::Base58(inner) => write!(f, "Base58: {}", inner),
            Error::Bip32(inner) => write!(f, "BIP32: {}", inner),
            Error::Ecdsa(inner) => write!(f, "Ecdsa: {}", inner),
            Error::Key(inner) => write!(f, "Key: {}", inner),
        }
    }
}

impl<'de> serde::Deserialize<'de> for PaymentCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;

        use serde::de::Error;
        PaymentCode::try_from_str(s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::Address;

    use super::PaymentCode;

    #[test]
    fn parse_payment_code() {
        let code = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
        let code = PaymentCode::try_from_str(code).unwrap();

        let expected_notification_address = Address::from_str("1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW")
            .unwrap()
            .assume_checked();
        let actual_notification_address =
            Address::p2pkh(&code.notification_pubkey().unwrap(), code.0.network);

        assert_eq!(expected_notification_address, actual_notification_address);
    }
}
