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

use crate::mix::{AlternateIdentityRequest, StreamRequest};
use serde::Serialize;

use super::Error;
use crate::codec::stomp;
use crate::codec::stomp::encode;
use crate::util::z85;

const HEADER_POOL_ID: &str = "poolId";
const HEADER_WP_VERSION: &str = "protocolVersion";

const SEND_HEADERS: &[(&str, &str)] = &[(HEADER_WP_VERSION, crate::WP_VERSION)];

impl TryFrom<StreamRequest> for Vec<u8> {
    type Error = Error;

    fn try_from(message: StreamRequest) -> Result<Self, Self::Error> {
        let mut writer: Vec<u8> = Vec::with_capacity(256); // avoid frequent resizing
        match message {
            StreamRequest::Connect => Ok(encode::connect(&mut writer, "").map(|_| writer)?),

            StreamRequest::SubscribePool { pool_id } => Ok(encode::subscribe(
                &mut writer,
                "",
                "/private/reply",
                &[
                    (HEADER_POOL_ID, &pool_id),
                    (HEADER_WP_VERSION, crate::WP_VERSION),
                ],
            )
            .map(|_| writer)?),

            StreamRequest::RegisterInput {
                pool_id,
                utxo,
                signature,
                remixer,
                block_height,
            } => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct Payload {
                    pool_id: String,
                    utxo_hash: String,
                    utxo_index: u32,
                    signature: String,
                    liquidity: bool,
                    block_height: u32,
                }

                let payload = Payload {
                    pool_id,
                    utxo_hash: utxo.txid.to_string(),
                    utxo_index: utxo.vout,
                    signature,
                    liquidity: remixer,
                    block_height,
                };

                Ok(
                    encode::send(&mut writer, "/ws/registerInput", SEND_HEADERS, |w| {
                        serde_json::to_writer(w, &payload).map_err(|_| stomp::Error::WriteInnerBody)
                    })
                    .map(|_| writer)?,
                )
            }

            StreamRequest::ConfirmInput {
                mix_id,
                blinded_destination,
                user_hash,
            } => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct Payload {
                    mix_id: String,
                    blinded_bordereau_64: String,
                    user_hash: String,
                }

                let payload = Payload {
                    mix_id,
                    blinded_bordereau_64: z85::encode(blinded_destination.0),
                    user_hash,
                };

                Ok(
                    encode::send(&mut writer, "/ws/confirmInput", SEND_HEADERS, |w| {
                        serde_json::to_writer(w, &payload).map_err(|_| stomp::Error::WriteInnerBody)
                    })
                    .map(|_| writer)?,
                )
            }

            StreamRequest::Sign { mix_id, witness } => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct Payload {
                    mix_id: String,
                    witnesses_64: Vec<String>,
                }

                let payload = Payload {
                    mix_id,
                    witnesses_64: witness.to_vec().into_iter().map(z85::encode).collect(),
                };

                Ok(encode::send(&mut writer, "/ws/signing", SEND_HEADERS, |w| {
                    serde_json::to_writer(w, &payload).map_err(|_| stomp::Error::WriteInnerBody)
                })
                .map(|_| writer)?)
            }

            StreamRequest::Reveal {
                mix_id,
                destination,
            } => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct Payload {
                    mix_id: String,
                    receive_address: String,
                }

                let payload = Payload {
                    mix_id,
                    receive_address: destination.to_string(),
                };

                Ok(
                    encode::send(&mut writer, "/ws/revealOutput", SEND_HEADERS, |w| {
                        serde_json::to_writer(w, &payload).map_err(|_| stomp::Error::WriteInnerBody)
                    })
                    .map(|_| writer)?,
                )
            }
        }
    }
}

impl TryFrom<AlternateIdentityRequest> for Vec<u8> {
    type Error = Error;

    fn try_from(message: AlternateIdentityRequest) -> Result<Self, Self::Error> {
        match message {
            AlternateIdentityRequest::CheckOutput {
                receive_address,
                signature,
            } => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct Request {
                    receive_address: String,
                    signature: String,
                }

                let request = Request {
                    receive_address: receive_address.to_string(),
                    signature,
                };

                serde_json::to_vec(&request).map_err(Error::Json)
            }

            AlternateIdentityRequest::RegisterOutput {
                inputs_hash,
                unblinded_signature,
                destination,
                bordereau,
            } => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct Request {
                    inputs_hash: String,
                    unblinded_signed_bordereau64: String,
                    receive_address: String,
                    bordereau64: String,
                }

                let request = Request {
                    inputs_hash,
                    unblinded_signed_bordereau64: z85::encode(&unblinded_signature.0),
                    receive_address: destination.to_string(),
                    bordereau64: z85::encode(bordereau),
                };

                serde_json::to_vec(&request).map_err(Error::Json)
            }
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::Json(error)
    }
}

impl From<stomp::Error> for Error {
    fn from(error: stomp::Error) -> Self {
        Self::Stomp(error)
    }
}
