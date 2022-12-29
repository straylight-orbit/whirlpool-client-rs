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

use bitcoin::util::bip32;
use bitcoin::util::psbt;
use bitcoin::{Address, Script, Transaction, TxIn, Witness};
use serde::{Deserialize, Serialize};

use crate::endpoints::Endpoints;
use crate::pool::Pool;
use crate::util::fee::MinerFee;
use crate::util::z85;
use crate::util::{self, bip47, bip69};
use crate::{http, Input, OutputTemplate};

/// The premix value of a TX0 transaction.
#[derive(Debug)]
pub struct PremixValue(u64);

impl PremixValue {
    pub fn new(pool: &Pool, fee_per_vbyte: f64) -> Self {
        let mix_tx_size = util::fee::estimate_mix_tx_size(pool.min_anonymity_set);
        let fee = ((mix_tx_size / pool.min_must_mix as f64) * fee_per_vbyte as f64).ceil() as u64;
        let premix_value = pool.denomination + fee;

        // Clamp the mix fee to the acceptable range for the pool.
        let premix_value = premix_value
            .min(pool.must_mix_balance_cap)
            .max(pool.must_mix_balance_min);

        Self(premix_value)
    }
}

/// Contains the preview of how a TX0 will look.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Preview {
    premix_value: u64,
    n_premix_outputs: u16,
    miner_fee: u64,
    coordinator_fee: CoordinatorFee,
    change: u64,
}

impl Preview {
    /// Computes a TX0 preview containing output values that can be used to construct a real TX0.
    /// If the result is `None`, it means that the total value of inputs is insufficient
    /// to successully construct one.
    pub fn new(
        inputs_value: u64,
        premix_value: &PremixValue,
        input_structure: &InputStructure,
        miner_fee: &MinerFee,
        coordinator_fee: CoordinatorFee,
        n_wanted_max_outputs: Option<u16>,
        n_pool_max_outputs: u16,
    ) -> Option<Self> {
        let premix_value = premix_value.0;
        let available = inputs_value;

        let available = available.checked_sub(coordinator_fee.value())?;

        let n_premix_outputs = (available / premix_value)
            // first cap the number of outputs to the desired max figure if provided
            .min(n_wanted_max_outputs.unwrap_or(u16::MAX) as u64)
            // then cap to the max allowed number of outputs as set by the pool
            .min(n_pool_max_outputs as u64);

        if n_premix_outputs < 1 {
            return None;
        }

        let premix_output_sum = premix_value * n_premix_outputs;
        let available = available.checked_sub(premix_output_sum)?;

        let miner_fee = match miner_fee {
            MinerFee::PerVByte(rate) => {
                rate * util::fee::estimate_tx0_size(
                    input_structure.n_p2pkh_inputs,
                    input_structure.n_p2sh_p2wpkh_inputs,
                    input_structure.n_p2wpkh_inputs,
                    n_premix_outputs as usize + 2,
                )
                .ceil() as u64
            }
            MinerFee::Fixed(fee) => *fee,
        };

        let available = available.checked_sub(miner_fee)?;

        Some(Self {
            premix_value,
            n_premix_outputs: n_premix_outputs as u16,
            miner_fee,
            coordinator_fee,
            change: available,
        })
    }

    /// Returns the total value consumed by this transaction, including of any change and fees.
    pub fn total_value(&self) -> u64 {
        self.premix_value * (self.n_premix_outputs as u64)
            + self.miner_fee
            + self.change
            + self.coordinator_fee.value()
    }

    /// Returns the number of premix outputs in the transaction.
    pub fn n_premix_outputs(&self) -> u16 {
        self.n_premix_outputs
    }

    /// Creates a PSBT ready for signing from this TX0 preview. If `true` is passed to
    /// `output_supplier`, it is supposed to return a change output template. Otherwise premix
    /// output template.
    pub fn into_psbt<OutputSupplier: FnMut(bool) -> OutputTemplate>(
        self,
        tx0_data: &Tx0Data,
        mut inputs: Vec<Input>,
        mut output_supplier: OutputSupplier,
    ) -> Result<psbt::PartiallySignedTransaction, Error> {
        let input_value: u64 = inputs.iter().map(|details| details.prev_txout.value).sum();

        // Ensure input value is sufficient for this tx0
        if self.total_value() != input_value {
            return Err(Error::InputValueMismatch);
        }

        // BIP 69 sort inputs
        inputs.sort_by(|a, b| {
            bip69::ComparableOutpoint(&a.outpoint).cmp(&bip69::ComparableOutpoint(&b.outpoint))
        });

        // Create the OP_RETURN payload
        let first_input = inputs.first().ok_or(Error::InputListEmpty)?;
        let mut fee_payload = z85::decode(&tx0_data.fee_payload_64).ok_or(Error::Z85)?;
        fee_payload.resize(80, 0);

        let fee_payment_code =
            bip47::PaymentCode::try_from_str(&tx0_data.fee_payment_code).map_err(Error::BIP47)?;

        let blinding_sk =
            bitcoin::secp256k1::SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng());
        let blinding_sk = bitcoin::PrivateKey::new(blinding_sk, fee_payment_code.0.network);

        mask_fee_payload(
            &mut fee_payload,
            &fee_payment_code,
            &first_input,
            &blinding_sk,
        )?;

        // Store raw TxOuts and their PSBT counterparts here
        let mut tx_outputs = Vec::with_capacity(3 + self.n_premix_outputs as usize);

        // OP_RETURN for the fee payload
        let op_return = bitcoin::TxOut {
            script_pubkey: bitcoin::Script::new_op_return(&fee_payload),
            value: 0,
        };
        tx_outputs.push((op_return, None));

        // Whirlpool fee or back deposit (discount) output
        let (fee_output, fee_out_fields) = match self.coordinator_fee {
            CoordinatorFee::DepositBack(value) => {
                let back_to_self = output_supplier(true);
                (
                    bitcoin::TxOut {
                        script_pubkey: back_to_self.address.script_pubkey(),
                        value,
                    },
                    back_to_self.fields,
                )
            }
            CoordinatorFee::Coordinator(value, fee_address) => {
                let coordinator_fields = psbt::Output::default();
                (
                    bitcoin::TxOut {
                        script_pubkey: fee_address.script_pubkey(),
                        value,
                    },
                    coordinator_fields,
                )
            }
        };
        tx_outputs.push((fee_output, Some(fee_out_fields)));

        // Premix outputs
        for _ in 0..self.n_premix_outputs {
            let premix_template = output_supplier(false);
            let txout = bitcoin::TxOut {
                script_pubkey: premix_template.address.script_pubkey(),
                value: self.premix_value,
            };
            tx_outputs.push((txout, Some(premix_template.fields)));
        }

        // Change output, if any
        if self.change > 0 {
            let change_template = output_supplier(true);
            let change_output = bitcoin::TxOut {
                script_pubkey: change_template.address.script_pubkey(),
                value: self.change,
            };
            tx_outputs.push((change_output, Some(change_template.fields)));
        }

        // BIP69 sort raw outs and their PSBT fields
        tx_outputs
            .sort_by(|(a, _), (b, _)| bip69::ComparableTxOut(&a).cmp(&bip69::ComparableTxOut(&b)));

        // Make inputs
        let raw_tx_ins = inputs
            .iter()
            .map(|details| TxIn {
                previous_output: details.outpoint,
                sequence: bitcoin::Sequence::MAX,
                script_sig: Script::new(),
                witness: Witness::new(),
            })
            .collect();

        // Prepare outputs for inserting into a tx
        let (raw_tx_outs, psbt_outs): (Vec<_>, Vec<_>) = tx_outputs.into_iter().unzip();
        debug_assert_eq!(raw_tx_outs.len(), psbt_outs.len());

        // Craft a transaction
        let unsigned_tx = Transaction {
            input: raw_tx_ins,
            output: raw_tx_outs,
            lock_time: bitcoin::PackedLockTime::ZERO,
            version: 1,
        };

        // Turn it into a PSBT
        let psbt = psbt::PartiallySignedTransaction {
            unsigned_tx,
            inputs: inputs.into_iter().map(|i| i.fields).collect(),
            outputs: psbt_outs
                .into_iter()
                .map(|o| o.unwrap_or_default())
                .collect(),
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
        };

        Ok(psbt)
    }
}

#[derive(Debug)]
pub enum Error {
    InputListEmpty,
    InputValueMismatch,
    OutputAddressMismatch,
    BIP32(bip32::Error),
    BIP47(bip47::Error),
    Secp256k1(bitcoin::secp256k1::Error),
    Z85,
    InvalidAddress(bitcoin::util::address::Error),
    Signing(Box<dyn std::error::Error + Send + Sync>),
    Blinding,
}

impl From<bip47::Error> for Error {
    fn from(error: bip47::Error) -> Self {
        Error::BIP47(error)
    }
}

fn mask_fee_payload(
    data: &mut [u8],
    fee_payment_code: &bip47::PaymentCode,
    input: &Input,
    blinding_sk: &bitcoin::PrivateKey,
) -> Result<(), Error> {
    let notification_pubkey = fee_payment_code.notification_pubkey()?;

    let blinding_factor =
        bip47::blinding_factor(&blinding_sk, &notification_pubkey, &input.outpoint)
            .map_err(Error::Secp256k1)?;

    data.iter_mut()
        .zip(blinding_factor.iter())
        .for_each(|(a, b)| {
            *a ^= b;
        });

    let data_len = data.len();
    let mut to_fill = data
        .get_mut(data_len - 34..data_len)
        .ok_or(Error::Blinding)?;
    blinding_sk
        .public_key(&bitcoin::secp256k1::Secp256k1::new())
        .write_into(&mut to_fill)
        .map_err(|_| Error::Blinding)?;
    *to_fill.last_mut().ok_or(Error::Blinding)? = 0x01;

    Ok(())
}

/// Coordinator fee. That can be either a real fee to the coordinator or a refund to self.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq))]
pub enum CoordinatorFee {
    DepositBack(u64),
    Coordinator(u64, Address),
}

impl CoordinatorFee {
    pub fn value(&self) -> u64 {
        match self {
            CoordinatorFee::DepositBack(v) => *v,
            CoordinatorFee::Coordinator(v, _) => *v,
        }
    }
}

/// Used during TX0 fee computation. Needed because different script types have different lengths.
pub struct InputStructure {
    pub n_p2pkh_inputs: usize,
    pub n_p2sh_p2wpkh_inputs: usize,
    pub n_p2wpkh_inputs: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tx0Data {
    pub pool_id: String,
    pub fee_payment_code: String,
    pub fee_value: u64,
    pub fee_change: u64,
    pub fee_discount_percent: u8,
    pub message: Option<String>,
    pub fee_payload_64: String,
    pub fee_address: Option<Address>,
    pub fee_output_signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tx0DataResponse {
    pub tx0_datas: Vec<Tx0Data>,
}

impl From<Tx0DataResponse> for Vec<Tx0Data> {
    fn from(response: Tx0DataResponse) -> Self {
        response.tx0_datas
    }
}

impl Tx0Data {
    pub fn request(endpoints: &Endpoints, scode: Option<String>) -> http::Request<Tx0DataResponse> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RequestPayload {
            scode: Option<String>,
            partner_id: &'static str,
        }

        let request = RequestPayload {
            scode,
            partner_id: std::option_env!("WPID").unwrap_or("FREESIDE"),
        };

        http::Request {
            url: endpoints.tx0_data.clone(),
            method: http::Method::POST,
            body: Some(http::Body::json(&request)),
            alt_id: false,
            de_type: std::marker::PhantomData,
        }
    }

    pub fn coordinator_fee(&self) -> CoordinatorFee {
        match &self.fee_address {
            Some(addr) => CoordinatorFee::Coordinator(self.fee_value, addr.clone()),
            None => CoordinatorFee::DepositBack(self.fee_change),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Tx0PushResponse {
    Ok {
        txid: String,
    },
    Error {
        message: Option<String>,
        #[serde(rename = "pushTxErrorCode")]
        push_tx_error_code: Option<String>,
        #[serde(rename = "voutsAddressReuse")]
        vouts_address_reuse: Option<Vec<u16>>,
    },
}

/// Creates HTTP request metadata for a tx0 push.
pub fn push_tx0_request(
    endpoints: &Endpoints,
    tx: &bitcoin::Transaction,
    pool_id: String,
) -> http::Request<Tx0PushResponse> {
    use bitcoin::consensus::Encodable;
    let mut tx_bytes = Vec::new();
    let _never_fail = tx.consensus_encode(&mut tx_bytes);

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RequestPayload {
        tx64: String,
        pool_id: String,
    }

    let request = RequestPayload {
        tx64: z85::encode(tx_bytes),
        pool_id,
    };

    http::Request {
        url: endpoints.tx0_push.clone(),
        method: http::Method::POST,
        body: Some(http::Body::json(&request)),
        alt_id: false,
        de_type: std::marker::PhantomData,
    }
}

#[cfg(test)]
mod test {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{OutPoint, PrivateKey, TxOut};

    use std::str::FromStr;

    use super::*;
    use crate::pool;

    const INPUT_STRUCTURE: InputStructure = InputStructure {
        n_p2pkh_inputs: 0,
        n_p2sh_p2wpkh_inputs: 0,
        n_p2wpkh_inputs: 1,
    };
    const N_POOL_MAX_OUTPUTS: u16 = 20;

    // no coordinator fee, 5 BTC in, 10 premix outputs
    #[test]
    fn compute_tx0_0() {
        let expected = Preview {
            premix_value: 1_000_201,
            n_premix_outputs: 10,
            coordinator_fee: CoordinatorFee::DepositBack(10_000),
            miner_fee: 543,
            change: 489_987_447,
        };

        assert_tx0_preview(
            MinerFee::PerVByte(1),
            expected.coordinator_fee.clone(),
            500_000_000,
            1_000_201,
            Some(10),
            Some(expected),
        );
    }

    // with a 5000 sat coordinator fee, 0.01021397 BTC in, 1 premix outputs
    #[test]
    fn compute_tx0_1() {
        let expected = Preview {
            premix_value: 1_000_150,
            n_premix_outputs: 1,
            coordinator_fee: CoordinatorFee::DepositBack(5000),
            miner_fee: 1,
            change: 16246,
        };

        assert_tx0_preview(
            MinerFee::Fixed(1),
            expected.coordinator_fee.clone(),
            1_021_397,
            1_000_150,
            None,
            Some(expected),
        );
    }

    // one scenario where we get 0 change back and one where we are short 1 sat
    #[test]
    fn compute_tx0_2() {
        let coordinator_fee = CoordinatorFee::DepositBack(1000);

        let expected = Preview {
            premix_value: 1_000_150,
            n_premix_outputs: 1,
            coordinator_fee: coordinator_fee.clone(),
            miner_fee: 1,
            change: 0,
        };

        // enough to get 0 change back
        assert_tx0_preview(
            MinerFee::Fixed(1),
            expected.coordinator_fee.clone(),
            1_001_151,
            1_000_150,
            None,
            Some(expected),
        );

        // short 1 sat
        assert_tx0_preview(
            MinerFee::Fixed(1),
            coordinator_fee.clone(),
            1_001_150,
            1_000_150,
            None,
            None,
        );
    }

    // with a 10000 sat coordinator fee, 5 BTC in, max out premix outputs (pool max)
    #[test]
    fn compute_tx0_3() {
        let expected = Preview {
            premix_value: 1_000_150,
            n_premix_outputs: N_POOL_MAX_OUTPUTS,
            coordinator_fee: CoordinatorFee::DepositBack(10_000),
            miner_fee: 1234,
            change: 479985766,
        };

        assert_tx0_preview(
            MinerFee::Fixed(1234),
            expected.coordinator_fee.clone(),
            500_000_000,
            1_000_150,
            Some(500), // this should be ignored as it is > pool max
            Some(expected),
        );
    }

    // with a 10000 sat coordinator fee, 5 BTC in, cap premix outputs (own limit)
    #[test]
    fn compute_tx0_4() {
        let expected = Preview {
            premix_value: 1_000_150,
            n_premix_outputs: 10,
            coordinator_fee: CoordinatorFee::DepositBack(10_000),
            miner_fee: 1234,
            change: 489987266,
        };

        assert_tx0_preview(
            MinerFee::Fixed(1234),
            expected.coordinator_fee.clone(),
            500_000_000,
            1_000_150,
            Some(10),
            Some(expected),
        );
    }

    #[test]
    fn premix_value() {
        let pool = Pool {
            id: "0.01btc".to_string(),
            denomination: 1_000_000,
            fee_value: 5000,
            must_mix_balance_min: 1_000_170,
            must_mix_balance_cap: 1_009_690,
            min_anonymity_set: 5,
            min_must_mix: 2,
            tx0_max_outputs: 70,
            n_registered: 277,
            mix_status: pool::MixStatus::ConfirmInput,
            elapsed_time: 1234,
            n_confirmed: 2,
        };

        assert_eq!(PremixValue::new(&pool, 0.0).0, pool.must_mix_balance_min);
        assert_eq!(PremixValue::new(&pool, 1.0).0, 1_000_253);
        assert_eq!(PremixValue::new(&pool, 2.0).0, 1_000_505);
        assert_eq!(PremixValue::new(&pool, 50.0).0, pool.must_mix_balance_cap);
        assert_eq!(PremixValue::new(&pool, 100.0).0, pool.must_mix_balance_cap);
    }

    #[test]
    fn mask_payload() {
        let fee_payment_code = bip47::PaymentCode::try_from_str("PM8TJXp19gCE6hQzqRi719FGJzF6AreRwvoQKLRnQ7dpgaakakFns22jHUqhtPQWmfevPQRCyfFbdDrKvrfw9oZv5PjaCerQMa3BKkPyUf9yN1CDR3w6").unwrap();
        let blinding_sk =
            PrivateKey::from_str("cTo4M7xXp9ZqRGseEYT2wVaZptYvbBSwap3PGN4NZ4ufA9d5MwL4").unwrap();

        let mut fee_payload: Vec<u8> = vec![0; 80];

        let input = Input {
            outpoint: bitcoin::OutPoint::default(),
            prev_txout: bitcoin::TxOut::default(),
            fields: psbt::Input::default(),
        };

        mask_fee_payload(&mut fee_payload, &fee_payment_code, &input, &blinding_sk).unwrap();

        assert_eq!(
            &fee_payload[46..79],
            &blinding_sk.public_key(&Secp256k1::new()).to_bytes()
        );
        assert_eq!(fee_payload[79], 0x01);
    }

    #[test]
    fn psbt_creation_no_coordinator_fee() {
        psbt_creation_from_preview(true)
    }
    #[test]
    fn psbt_creation_with_coordinator_fee() {
        psbt_creation_from_preview(false)
    }

    fn psbt_creation_from_preview(no_coordinator_fee: bool) {
        let (fee_value, fee_change, fee_address) = match no_coordinator_fee {
            true => (0, 45000, None),
            false => (
                45000,
                0,
                Some(Address::from_str("1BvQpuGDq654ZMhsQKT3iQVTgxcRdCCfrR").unwrap()),
            ),
        };

        let inputs = vec![
            fake_input(
                "5e2383defe7efcbdc9fdd6dba55da148b206617bbb49e6bb93fce7bfbb459d44:1",
                5_000_000,
            ),
            fake_input(
                "1e2383defe7efcbdc9fdd6dba55da148b206617bbb49e6bb93fce7bfbb459d44:0",
                3_000_000,
            ),
            fake_input(
                "4e2383defe7efcbdc9fdd6dba55da148b206617bbb49e6bb93fce7bfbb459d44:5",
                1_000_000,
            ),
        ];
        let n_inputs = inputs.len();
        let inputs_value = inputs.iter().map(|i| i.prev_txout.value).sum();

        let tx0_data = Tx0Data {
            fee_address,
            fee_value,
            fee_change,
            fee_discount_percent: 0,
            fee_payload_64: "123.123.123".to_string(),
            fee_payment_code: "PM8TJXp19gCE6hQzqRi719FGJzF6AreRwvoQKLRnQ7dpgaakakFns22jHUqhtPQWmfevPQRCyfFbdDrKvrfw9oZv5PjaCerQMa3BKkPyUf9yN1CDR3w6".to_string(),
            pool_id: String::new(),
            message: None,
            fee_output_signature: "II4wrLMNJxchyrcu0aVB8FbrCFIO6YSKpZW5qfc1DO7NCkl4hihArn3aLcP0ylN5Z/UDbxWwzd4l9huO1hcsK/E=".to_string(),
        };

        let premix_value = 1_000_170;
        let preview = Preview::new(
            inputs_value,
            &PremixValue(premix_value),
            &InputStructure {
                n_p2pkh_inputs: 0,
                n_p2sh_p2wpkh_inputs: 0,
                n_p2wpkh_inputs: inputs.len(),
            },
            &MinerFee::PerVByte(1),
            tx0_data.coordinator_fee(),
            None,
            100,
        )
        .unwrap();
        let miner_fee = preview.miner_fee;
        let change = preview.change;

        let change_addr = Address::from_str("1EgPiHUdLupfiUPg7ztJJzteTDcDvRJE3s").unwrap();
        let address_bank: Vec<_> = [
            "174WD5hStuHkywyonMf8wzGQLaj7RJp6M9",
            "1EuZwtFs6WNQRrSECbxTNFz3XkNfxUgygS",
            "18opzWnrXimEkEJto8QFhTD66VeEX9GzKw",
            "1LNSye3prTvA9ewSC8jiiJdsLTsTQPDqq9",
            "1FkWf9FwFiYuF19QLH72Vv1oiceB4aKc9d",
            "15W5wdh8S3PcLyRNqm7Wd1T3mg45qPVTaD",
            "14gmz3eeJiTgGUEVMFXDje3yDXEzKmNv7L",
            "12paNp3kuww3u3MYEbee5cWQefAaasWQbf",
            "179JVSwhKPAYn7vXjn4EBdiRHtqYK8FcLL",
            "1EKExobcKjtCyo2TAVX8RKCPMLLezUNa95",
            "16TL3mgmmvobehCCiQeTnQ1hR5xQDi77dz",
            "1KmhCoxmD4mW7MKAGwTqcqpACoZXjyjQNi",
        ]
        .iter()
        .map(|a| Address::from_str(a).unwrap())
        .collect();

        let mut next_addr = 0_usize;
        let psbt = preview
            .into_psbt(&tx0_data, inputs, |change| {
                if change {
                    OutputTemplate {
                        address: change_addr.clone(),
                        fields: psbt::Output {
                            redeem_script: Some(Script::new_op_return(&[0xFF])),
                            ..Default::default()
                        },
                    }
                } else {
                    let address = address_bank[next_addr].clone();
                    let res = OutputTemplate {
                        address: address.clone(),
                        fields: psbt::Output {
                            redeem_script: Some(address.script_pubkey()),
                            ..Default::default()
                        },
                    };
                    next_addr += 1;
                    res
                }
            })
            .unwrap();

        // verify input/output counts
        assert_eq!(psbt.inputs.len(), n_inputs);
        assert_eq!(psbt.outputs.len(), 8 + 3); // premix + fee + change + op_return

        // verify inputs
        for (i, (raw_in, psbt_in)) in psbt
            .unsigned_tx
            .input
            .iter()
            .zip(psbt.inputs.iter())
            .enumerate()
        {
            let expected_marker = raw_in.previous_output.txid.as_hash().into_inner();
            assert_eq!(
                Script::new_op_return(&expected_marker),
                psbt_in.witness_utxo.as_ref().unwrap().script_pubkey,
            );

            if i == 0 {
                assert_eq!(
                    "1e2383defe7efcbdc9fdd6dba55da148b206617bbb49e6bb93fce7bfbb459d44:0",
                    raw_in.previous_output.to_string()
                );
            } else if i == 1 {
                assert_eq!(
                    "4e2383defe7efcbdc9fdd6dba55da148b206617bbb49e6bb93fce7bfbb459d44:5",
                    raw_in.previous_output.to_string()
                );
            } else {
                assert_eq!(
                    "5e2383defe7efcbdc9fdd6dba55da148b206617bbb49e6bb93fce7bfbb459d44:1",
                    raw_in.previous_output.to_string()
                );
            }
        }

        // verify outputs
        let mut total_out = 0;
        for (i, (raw_out, psbt_out)) in psbt
            .unsigned_tx
            .output
            .iter()
            .zip(psbt.outputs.iter())
            .enumerate()
        {
            total_out += raw_out.value;
            if i == 0 {
                assert!(raw_out.script_pubkey.is_op_return());
                assert_eq!(raw_out.value, 0);
            } else if i == 1 {
                assert_eq!(raw_out.value, 45000);
                let fee_address = if no_coordinator_fee {
                    &change_addr
                } else {
                    &tx0_data.fee_address.as_ref().unwrap()
                };
                assert_eq!(raw_out.script_pubkey, fee_address.script_pubkey());
            } else if i == 2 {
                assert_eq!(raw_out.value, change);
                assert_eq!(raw_out.script_pubkey, change_addr.script_pubkey());
                assert_eq!(psbt_out.redeem_script, Some(Script::new_op_return(&[0xFF])));
            } else {
                assert_eq!(raw_out.value, premix_value);
                assert_eq!(
                    psbt_out.redeem_script.as_ref(),
                    Some(&raw_out.script_pubkey)
                );
            }
        }

        assert_eq!(inputs_value - total_out, miner_fee);
    }

    fn fake_input(outpoint: &str, value: u64) -> Input {
        // this wouldn't make any sense in reality, but we just want to check
        // that our PSBT is constructed properly
        let outpoint = OutPoint::from_str(outpoint).unwrap();
        let prev_txout = TxOut {
            value,
            script_pubkey: Script::new_op_return(outpoint.txid.as_hash().as_inner()),
        };
        Input {
            outpoint,
            prev_txout: prev_txout.clone(),
            fields: psbt::Input {
                witness_utxo: Some(prev_txout),
                ..Default::default()
            },
        }
    }

    fn assert_tx0_preview(
        miner_fee: MinerFee,
        coordinator_fee: CoordinatorFee,
        inputs_value: u64,
        premix_value: u64,
        n_wanted_max_outputs: Option<u16>,
        expected: Option<Preview>,
    ) {
        let actual = Preview::new(
            inputs_value,
            &PremixValue(premix_value),
            &INPUT_STRUCTURE,
            &miner_fee,
            coordinator_fee,
            n_wanted_max_outputs,
            N_POOL_MAX_OUTPUTS,
        );

        assert_eq!(actual, expected);
        if let Some(actual) = actual {
            assert_eq!(actual.total_value(), inputs_value);
        }
    }
}
