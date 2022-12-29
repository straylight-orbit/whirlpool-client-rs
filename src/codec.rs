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

mod decode;
mod encode;
mod stomp;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Stomp(stomp::Error),
    Json(serde_json::Error),
    Z85,
    RSA(blind_rsa_signatures::Error),
    Bitcoin(bitcoin::consensus::encode::Error),
    UnsupportedNetwork(String),
    UnknownWhirlpoolMessage,
    UnsolictedMessage,
    ServerError(String),
}
