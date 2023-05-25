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

use std::cmp::Ordering;

use bitcoin::blockdata::transaction::{TxIn, TxOut};
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;

/// Lexicographically comparable wrapper for an outpoint according to BIP69.
#[derive(PartialEq, Eq, PartialOrd)]
pub struct ComparableOutpoint<'a>(pub &'a OutPoint);

impl<'a> std::cmp::Ord for ComparableOutpoint<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self
            .0
            .txid
            .to_byte_array()
            .iter()
            .rev()
            .cmp(other.0.txid.to_byte_array().iter().rev())
        {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => self.0.vout.cmp(&other.0.vout),
        }
    }
}

/// Lexicographically comparable wrapper for a txout according to BIP69.
#[derive(PartialEq, Eq, PartialOrd)]
pub struct ComparableTxOut<'a>(pub &'a TxOut);

impl<'a> std::cmp::Ord for ComparableTxOut<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.0.value.cmp(&other.0.value) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => self.0.script_pubkey.cmp(&other.0.script_pubkey),
        }
    }
}

/// Lexicographically sorts a vector of transaction inputs according to BIP69.
pub fn sort_inputs(inputs: &mut [TxIn]) {
    inputs.sort_by(|a, b| {
        ComparableOutpoint(&a.previous_output).cmp(&ComparableOutpoint(&b.previous_output))
    })
}

/// Lexicographically sorts a vector of transaction outputs according to BIP69.
pub fn sort_outputs(outputs: &mut [TxOut]) {
    outputs.sort_by(|a, b| ComparableTxOut(a).cmp(&ComparableTxOut(b)))
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
    use bitcoin::ScriptBuf;

    use super::{sort_inputs, sort_outputs};

    #[test]
    fn sort_inputs_1() {
        let unsorted = vec![
            "643e5f4e66373a57251fb173151e838ccd27d279aca882997e005016bb53d5aa:0",
            "28e0fdd185542f2c6ea19030b0796051e7772b6026dd5ddccd7a2f93b73e6fc2:0",
            "f0a130a84912d03c1d284974f563c5949ac13f8342b8112edff52971599e6a45:0",
            "0e53ec5dfb2cb8a71fec32dc9a634a35b7e24799295ddd5278217822e0b31f57:0",
            "381de9b9ae1a94d9c17f6a08ef9d341a5ce29e2e60c36a52d333ff6203e58d5d:1",
            "f320832a9d2e2452af63154bc687493484a0e7745ebd3aaf9ca19eb80834ad60:0",
            "de0411a1e97484a2804ff1dbde260ac19de841bebad1880c782941aca883b4e9:1",
            "3b8b2f8efceb60ba78ca8bba206a137f14cb5ea4035e761ee204302d46b98de2:0",
            "54ffff182965ed0957dba1239c27164ace5a73c9b62a660c74b7b7f15ff61e7a:1",
            "bafd65e3c7f3f9fdfdc1ddb026131b278c3be1af90a4a6ffa78c4658f9ec0c85:0",
            "a5e899dddb28776ea9ddac0a502316d53a4a3fca607c72f66c470e0412e34086:0",
            "7a1de137cbafb5c70405455c49c5104ca3057a1f1243e6563bb9245c9c88c191:0",
            "26aa6e6d8b9e49bb0630aac301db6757c02e3619feb4ee0eea81eb1672947024:1",
            "402b2c02411720bf409eff60d05adad684f135838962823f3614cc657dd7bc0a:1",
            "7d037ceb2ee0dc03e82f17be7935d238b35d1deabf953a892a4507bfbeeb3ba4:1",
            "6c1d56f31b2de4bfc6aaea28396b333102b1f600da9c6d6149e96ca43f1102b1:1",
            "b4112b8f900a7ca0c8b0e7c4dfad35c6be5f6be46b3458974988e1cdb2fa61b8:0",
        ];

        let expected_sorted = vec![
            "0e53ec5dfb2cb8a71fec32dc9a634a35b7e24799295ddd5278217822e0b31f57:0",
            "26aa6e6d8b9e49bb0630aac301db6757c02e3619feb4ee0eea81eb1672947024:1",
            "28e0fdd185542f2c6ea19030b0796051e7772b6026dd5ddccd7a2f93b73e6fc2:0",
            "381de9b9ae1a94d9c17f6a08ef9d341a5ce29e2e60c36a52d333ff6203e58d5d:1",
            "3b8b2f8efceb60ba78ca8bba206a137f14cb5ea4035e761ee204302d46b98de2:0",
            "402b2c02411720bf409eff60d05adad684f135838962823f3614cc657dd7bc0a:1",
            "54ffff182965ed0957dba1239c27164ace5a73c9b62a660c74b7b7f15ff61e7a:1",
            "643e5f4e66373a57251fb173151e838ccd27d279aca882997e005016bb53d5aa:0",
            "6c1d56f31b2de4bfc6aaea28396b333102b1f600da9c6d6149e96ca43f1102b1:1",
            "7a1de137cbafb5c70405455c49c5104ca3057a1f1243e6563bb9245c9c88c191:0",
            "7d037ceb2ee0dc03e82f17be7935d238b35d1deabf953a892a4507bfbeeb3ba4:1",
            "a5e899dddb28776ea9ddac0a502316d53a4a3fca607c72f66c470e0412e34086:0",
            "b4112b8f900a7ca0c8b0e7c4dfad35c6be5f6be46b3458974988e1cdb2fa61b8:0",
            "bafd65e3c7f3f9fdfdc1ddb026131b278c3be1af90a4a6ffa78c4658f9ec0c85:0",
            "de0411a1e97484a2804ff1dbde260ac19de841bebad1880c782941aca883b4e9:1",
            "f0a130a84912d03c1d284974f563c5949ac13f8342b8112edff52971599e6a45:0",
            "f320832a9d2e2452af63154bc687493484a0e7745ebd3aaf9ca19eb80834ad60:0",
        ];

        sort_inputs_and_assert(unsorted, expected_sorted);
    }

    #[test]
    fn sort_inputs_2() {
        let unsorted = vec![
            "35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055:1",
            "35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055:0",
        ];

        let expected_sorted = vec![
            "35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055:0",
            "35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055:1",
        ];

        sort_inputs_and_assert(unsorted, expected_sorted);
    }

    fn sort_inputs_and_assert(unsorted: Vec<&str>, expected_sorted: Vec<&str>) {
        let mut inputs: Vec<_> = unsorted
            .into_iter()
            .map(|input| TxIn {
                previous_output: OutPoint::from_str(input).unwrap(),
                ..Default::default()
            })
            .collect();

        sort_inputs(&mut inputs);

        assert_eq!(inputs.len(), expected_sorted.len());

        for (actual, expected) in inputs
            .iter()
            .map(|txin| txin.previous_output.to_string())
            .zip(expected_sorted)
        {
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn sort_outputs_1() {
        let unsorted = vec![
            (
                "40000000000",
                "76a9145be32612930b8323add2212a4ec03c1562084f8488ac",
            ),
            (
                "400057456",
                "76a9144a5fba237213a062f6f57978f796390bdcf8d01588ac",
            ),
        ];

        let expected_sorted = vec![
            (
                "400057456",
                "76a9144a5fba237213a062f6f57978f796390bdcf8d01588ac",
            ),
            (
                "40000000000",
                "76a9145be32612930b8323add2212a4ec03c1562084f8488ac",
            ),
        ];

        sort_outputs_and_assert(unsorted, expected_sorted);
    }

    #[test]
    fn sort_outputs_2() {
        let unsorted = vec![
            (
                "2400000000",
                "41044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac"
            ),
            (
                "100000000",
                "41046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac"
            ),
        ];

        let expected_sorted = vec![
            (
                "100000000",
                "41046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac"
            ),
            (
                "2400000000",
                "41044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac"
            ),
        ];

        sort_outputs_and_assert(unsorted, expected_sorted);
    }

    #[test]
    fn sort_outputs_3() {
        let unsorted = vec![
            ("1000", "76a9145be32612930b8323add2212a4ec03c1562084f8488ac"),
            ("1000", "76a9144a5fba237213a062f6f57978f796390bdcf8d01588ac"),
        ];

        let expected_sorted = vec![
            ("1000", "76a9144a5fba237213a062f6f57978f796390bdcf8d01588ac"),
            ("1000", "76a9145be32612930b8323add2212a4ec03c1562084f8488ac"),
        ];

        sort_outputs_and_assert(unsorted, expected_sorted);
    }

    fn sort_outputs_and_assert(unsorted: Vec<(&str, &str)>, expected_sorted: Vec<(&str, &str)>) {
        let mut outputs: Vec<_> = unsorted
            .into_iter()
            .map(|(value, scriptpubkey)| TxOut {
                value: value.parse().unwrap(),
                script_pubkey: ScriptBuf::from_hex(&scriptpubkey).unwrap(),
            })
            .collect();

        sort_outputs(&mut outputs);

        assert_eq!(outputs.len(), expected_sorted.len());

        for (actual, expected) in outputs.iter().zip(expected_sorted) {
            assert_eq!(actual.value, u64::from_str(expected.0).unwrap());
            assert_eq!(
                actual.script_pubkey,
                ScriptBuf::from_hex(expected.1).unwrap()
            );
        }
    }
}
