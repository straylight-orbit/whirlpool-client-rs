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

const P2PKH_IN_SIZE: f64 = 148.0;
const P2SH_P2WPKH_IN_SIZE: f64 = 91.0;
const P2WPKH_IN_SIZE: f64 = 67.75;
const P2WPKH_OUT_SIZE: f64 = 31.0;
const OP_RETURN_SIZE: f64 = 92.0;
const N_TX0_OP_RETURNS: usize = 1;

// segwit_marker + segwit_flag + witness_element_count
const WITNESS_MARKER: f64 = 0.50;
const WITNESS_ITEMS: f64 = 0.25;

/// Transaction mining fee that is either fixed or expressed per vByte.
#[derive(Debug)]
pub enum MinerFee {
    PerVByte(u64),
    Fixed(u64),
}

/// Estimates the size of a tx0 in vBytes.
pub fn estimate_tx0_size(
    n_p2pkh_inputs: usize,
    n_p2sh_p2wpkh_inputs: usize,
    n_p2wpkh_inputs: usize,
    n_p2wpkh_outputs: usize,
) -> f64 {
    let input_size = n_p2pkh_inputs as f64 * P2PKH_IN_SIZE
        + n_p2sh_p2wpkh_inputs as f64 * P2SH_P2WPKH_IN_SIZE
        + n_p2wpkh_inputs as f64 * P2WPKH_IN_SIZE
        + n_p2wpkh_inputs as f64 * WITNESS_ITEMS;

    let output_size =
        n_p2wpkh_outputs as f64 * P2WPKH_OUT_SIZE + N_TX0_OP_RETURNS as f64 * OP_RETURN_SIZE;

    let n_witness_inputs = n_p2wpkh_inputs + n_p2sh_p2wpkh_inputs;
    let n_total_inputs = n_witness_inputs + n_p2pkh_inputs;

    let overhead = {
        let witness_overhead = if n_witness_inputs > 0 {
            WITNESS_MARKER
        } else {
            0.0
        };

        4_f64 // nVersion
            + sizeof_varint(n_total_inputs) as f64
            + sizeof_varint(n_p2wpkh_outputs + N_TX0_OP_RETURNS) as f64
            + 4_f64 // nLockTime
            + witness_overhead
    };

    input_size + output_size + overhead
}

/// Estimates the size of a mix transaction in vBytes.
pub fn estimate_mix_tx_size(anonset: u16) -> f64 {
    let input_size = anonset as f64 * P2WPKH_IN_SIZE;
    let output_size = anonset as f64 * P2WPKH_OUT_SIZE;
    let overhead = 4_f64 // nVersion
            + sizeof_varint(anonset as usize) as f64 // inputs
            + sizeof_varint(anonset as usize) as f64 // outputs
            + 4_f64 // nLockTime
            + WITNESS_MARKER;

    input_size + output_size + overhead
}

fn sizeof_varint(int: usize) -> usize {
    match int {
        0..=252 => 1,
        253..=65534 => 3,
        65535..=4294967294 => 5,
        _ => 9,
    }
}
