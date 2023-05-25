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

use std::collections::HashMap;

use serde::Deserialize;

use crate::mix::CoordinatorResponse;
use crate::util::z85;

use super::{stomp::decode::ServerFrame, Error};

impl TryFrom<&[u8]> for CoordinatorResponse {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self, Error> {
        let frame = ServerFrame::parse(data)?;

        match frame {
            ServerFrame::Connected => Ok(CoordinatorResponse::Connected),

            ServerFrame::Message { body, headers } => {
                match message_type(&headers).ok_or(Error::UnknownWhirlpoolMessage)? {
                    "SubscribePoolResponse" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            network_id: String,
                            denomination: u64,
                            must_mix_balance_min: u64,
                            must_mix_balance_cap: u64,
                            must_mix_balance_max: u64,
                        }

                        let response: Response = serde_json::from_slice(body)?;

                        Ok(CoordinatorResponse::SubscribedPool {
                            network: parse_network(&response.network_id)?,
                            denomination: response.denomination,
                            min_amount: response.must_mix_balance_min,
                            cap_amount: response.must_mix_balance_cap,
                            max_amount: response.must_mix_balance_max,
                        })
                    }

                    "ConfirmInputMixStatusNotification" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            mix_id: String,
                            public_key_64: String,
                        }

                        let response: Response = serde_json::from_slice(body)?;
                        let public_key = blind_rsa_signatures::PublicKey::from_der(
                            &z85::decode(response.public_key_64).ok_or(Error::Z85)?,
                        )?;

                        Ok(CoordinatorResponse::ConfirmInputNotification {
                            mix_id: response.mix_id,
                            public_key,
                        })
                    }

                    "ConfirmInputResponse" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            mix_id: String,
                            signed_bordereau_64: String,
                        }

                        let response: Response = serde_json::from_slice(body)?;
                        let blind_signature = blind_rsa_signatures::BlindSignature::new(
                            z85::decode(&response.signed_bordereau_64).ok_or(Error::Z85)?,
                        );

                        if blind_signature.0.len() != 256 {
                            log::error!(
                                "BLIND_SIG error: length: {} Z85:\n{}\n",
                                blind_signature.0.len(),
                                response.signed_bordereau_64
                            );
                        }

                        Ok(CoordinatorResponse::ConfirmedInput {
                            mix_id: response.mix_id,
                            blind_signature,
                        })
                    }

                    "RegisterOutputMixStatusNotification" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            mix_id: String,
                            inputs_hash: String,
                        }

                        let response: Response = serde_json::from_slice(body)?;

                        Ok(CoordinatorResponse::RegisterOutputNotification {
                            mix_id: response.mix_id,
                            inputs_hash: response.inputs_hash,
                        })
                    }

                    "SigningMixStatusNotification" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            mix_id: String,
                            transaction_64: String,
                        }
                        use bitcoin::consensus::Decodable;

                        let response: Response = serde_json::from_slice(body)?;
                        let transaction_64 =
                            z85::decode(response.transaction_64).ok_or(Error::Z85)?;
                        let transaction =
                            bitcoin::Transaction::consensus_decode(&mut transaction_64.as_slice())?;

                        Ok(CoordinatorResponse::SigningNotification {
                            mix_id: response.mix_id,
                            transaction,
                        })
                    }

                    "SuccessMixStatusNotification" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            mix_id: String,
                        }

                        let response: Response = serde_json::from_slice(body)?;

                        Ok(CoordinatorResponse::MixSuccessful {
                            mix_id: response.mix_id,
                        })
                    }

                    "RevealOutputMixStatusNotification" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            mix_id: String,
                        }

                        let response: Response = serde_json::from_slice(body)?;

                        Ok(CoordinatorResponse::RevealNotification {
                            mix_id: response.mix_id,
                        })
                    }

                    "FailMixStatusNotification" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            mix_id: String,
                        }

                        let response: Response = serde_json::from_slice(body)?;

                        Ok(CoordinatorResponse::MixFailed {
                            mix_id: response.mix_id,
                        })
                    }

                    "ErrorResponse" => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Response {
                            error_code: u32,
                            message: String,
                        }

                        let response: Response = serde_json::from_slice(body)?;

                        Ok(CoordinatorResponse::Error {
                            code: response.error_code,
                            message: response.message,
                        })
                    }

                    _ => Err(Error::UnknownWhirlpoolMessage),
                }
            }

            ServerFrame::Receipt(_) => Err(Error::UnsolictedMessage),

            ServerFrame::Error(error) => Err(Error::ServerError(error.to_owned())),
        }
    }
}

fn message_type<'a>(headers: &'a HashMap<&'a str, &'a str>) -> Option<&'a str> {
    // example: com.samourai.whirlpool.protocol.websocket.messages.SubscribePoolResponse
    headers.get("messageType")?.split('.').nth_back(0)
}

fn parse_network(value: &str) -> Result<bitcoin::Network, Error> {
    match value {
        "main" => Ok(bitcoin::Network::Bitcoin),
        "test" => Ok(bitcoin::Network::Testnet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        other => Err(Error::UnsupportedNetwork(other.to_owned())),
    }
}

impl From<blind_rsa_signatures::Error> for Error {
    fn from(error: blind_rsa_signatures::Error) -> Self {
        Error::RSA(error)
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(error: bitcoin::consensus::encode::Error) -> Self {
        Error::Bitcoin(error)
    }
}
