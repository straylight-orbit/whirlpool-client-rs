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

pub mod bip47;
pub mod bip69;
pub mod fee;
pub mod z85;

pub mod hashes {
    use bitcoin::hashes::{sha256, Hash};

    /// Digests some data through a single sha256.
    pub fn sha256(b: &[u8]) -> sha256::Hash {
        sha256::Hash::hash(b)
    }
}
