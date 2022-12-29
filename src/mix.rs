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

use std::collections::HashSet;

use bitcoin::hashes::hex::ToHex;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{Address, OutPoint, Witness};

use crate::util;
use crate::Signer;
use crate::{Input, OutputTemplate};

/// Parameters required in order to start a mix.
#[derive(Debug)]
pub struct Params {
    /// The input entering a mix.
    pub input: Input,
    /// The signer to use.
    pub signer: Box<dyn Signer>,
    /// The destination output to mix to.
    pub destination: OutputTemplate,
    /// The pool to join.
    pub pool_id: String,
    /// The pool denomination in sats.
    pub denomination: u64,
    /// Some entropy that has to be unique per seed. This is to prevent multiple wallet
    /// instances with the same seed trying to join with the same inputs simultaneously.
    pub pre_user_hash: PreUserHash,
    /// The Bitcoin network to operate on.
    pub network: bitcoin::Network,
    /// The current block height.
    pub block_height: u32,
}

/// State machine representing a Whirlpool mix. Consumes events from the coordinator and
/// generates events to be sent to the coordinator.
#[derive(Debug)]
pub struct Mix {
    params: Params,
    id: Option<String>,
    state: State,
}

impl Mix {
    /// Creates a new mix state machine based on some mix parameters. Returns a state machine and
    /// the connect message that must be sent to the coordinator before any events can be received.
    pub fn new(params: Params) -> (Self, StreamRequest) {
        (
            Mix {
                params,
                id: None,
                state: State::Connect,
            },
            StreamRequest::Connect,
        )
    }

    /// Checks if the mix is in a state where leaving would cause the mix to fail and get this UTXO
    /// temporarily banned by the coordinator.
    pub fn must_stay(&self) -> bool {
        matches!(
            self.state,
            State::RegisterOutput { .. } | State::Sign(_) | State::RevealOutput
        )
    }

    /// Processes an event received from the coordinator and advances the state machine to the
    /// next step.
    pub fn process(&mut self, response: CoordinatorResponse) -> Result<Event, Error> {
        match (response, &self.state) {
            (CoordinatorResponse::Connected, State::Connect) => {
                self.change_state(State::Subscribe);

                let message = StreamRequest::SubscribePool {
                    pool_id: self.params.pool_id.clone(),
                };

                Ok(Event::StandardRequest(message))
            }

            (
                // We have subscribed to a pool.
                CoordinatorResponse::SubscribedPool { network, .. },
                State::Subscribe,
            ) => {
                if self.params.network != network {
                    return Err(Error::NetworkMismatch {
                        expected: self.params.network,
                        actual: network,
                    });
                }

                let message = StreamRequest::RegisterInput {
                    pool_id: self.params.pool_id.clone(),
                    utxo: self.params.input.outpoint,
                    signature: self
                        .params
                        .signer
                        .sign_message(&self.params.input, &self.params.pool_id)
                        .map_err(Error::Signing)?,
                    remixer: self.params.denomination == self.params.input.prev_txout.value,
                    block_height: self.params.block_height,
                };

                self.change_state(State::RegisterInput);

                Ok(Event::StandardRequest(message))
            }

            (
                // A new mix has been announced. We can get this more than once if we get requeued.
                CoordinatorResponse::ConfirmInputNotification { mix_id, public_key },
                State::RegisterInput | State::ConfirmInput { .. },
            ) => {
                let bordereau = Bordereau::new();
                let blinded = public_key.blind(&bordereau, &blinding_options())?;

                let user_hash = util::hashes::sha256(
                    &[&self.params.pre_user_hash.0, mix_id.as_bytes()].concat(),
                )
                .to_hex();

                let message = StreamRequest::ConfirmInput {
                    blinded_destination: blinded.blind_msg,
                    mix_id,
                    user_hash,
                };

                self.change_state(State::ConfirmInput {
                    blinding_secret: blinded.secret,
                    public_key,
                    bordereau,
                });

                Ok(Event::StandardRequest(message))
            }

            (
                // Our input has been confirmed. Guaranteed to be in the mix.
                CoordinatorResponse::ConfirmedInput {
                    mix_id,
                    blind_signature,
                },
                State::ConfirmInput {
                    blinding_secret,
                    public_key,
                    bordereau,
                },
            ) => {
                self.id = Some(mix_id);

                let signature = public_key.finalize(
                    &blind_signature,
                    &blinding_secret,
                    bordereau,
                    &blinding_options(),
                )?;

                let bordereau = bordereau.to_owned();

                self.change_state(State::ConfirmedInputWait {
                    signature,
                    bordereau,
                });

                Ok(Event::WaitForCoordinator)
            }

            (
                // We are told to register our output.
                CoordinatorResponse::RegisterOutputNotification {
                    inputs_hash,
                    mix_id,
                },
                State::ConfirmedInputWait {
                    signature,
                    bordereau,
                },
            ) => {
                self.verify_mix_id(&mix_id)?;

                self.id = Some(mix_id);

                let message = AlternateIdentityRequest::RegisterOutput {
                    destination: self.params.destination.address.clone(),
                    inputs_hash: inputs_hash.clone(),
                    unblinded_signature: signature.clone(),
                    bordereau: bordereau.clone(),
                };

                self.change_state(State::RegisterOutput { inputs_hash });

                Ok(Event::AltIdRequest(message))
            }

            (
                // Path A: We are asked to sign our input and reply with the witness.
                CoordinatorResponse::SigningNotification {
                    mix_id,
                    transaction,
                },
                State::RegisterOutput { inputs_hash },
            ) => {
                self.verify_mix_id(&mix_id)?;

                let (our_in_idx, our_out_idx) = verify_mix_tx(
                    &transaction,
                    &self.params.destination.address,
                    &self.params.input,
                    self.params.denomination,
                    &inputs_hash,
                )
                .map_err(Error::MixTransaction)?;

                let witness = {
                    let mut psbt =
                        PartiallySignedTransaction::from_unsigned_tx(transaction.clone())
                            .map_err(|_| MixTxError::TxAlreadySigned)
                            .map_err(Error::MixTransaction)?;

                    let our_input = &mut psbt.inputs[our_in_idx];
                    *our_input = self.params.input.fields.clone();
                    if our_input.witness_utxo.is_none() {
                        our_input.witness_utxo = Some(self.params.input.prev_txout.clone());
                    }

                    psbt.outputs[our_out_idx] = self.params.destination.fields.clone();

                    let mut signed = self.params.signer.sign_tx(psbt).map_err(Error::Signing)?;
                    let witness = std::mem::take(&mut signed.input[our_in_idx].witness);

                    if witness.is_empty() {
                        return Err(Error::MixTransaction(MixTxError::SignatureEmpty));
                    }

                    witness
                };

                let message = StreamRequest::Sign { mix_id, witness };

                self.change_state(State::Sign(transaction.txid()));

                Ok(Event::StandardRequest(message))
            }

            // Path A: The mix has completed successfully.
            (CoordinatorResponse::MixSuccessful { mix_id }, State::Sign(txid)) => {
                self.verify_mix_id(&mix_id)?;

                let event = Event::Success(txid.clone());
                self.change_state(State::Success);
                Ok(event)
            }

            // Path B: Someone caused the mix to fail. Must reveal our output.
            (
                CoordinatorResponse::RevealNotification { mix_id },
                State::RegisterOutput { .. } | State::Sign(_),
            ) => {
                self.verify_mix_id(&mix_id)?;

                let message = StreamRequest::Reveal {
                    destination: self.params.destination.address.clone(),
                    mix_id,
                };

                self.change_state(State::RevealOutput);

                Ok(Event::StandardRequest(message))
            }

            // Path B: The mix has failed on the coordinator side.
            (CoordinatorResponse::MixFailed { mix_id }, _) => {
                self.verify_mix_id(&mix_id)?;

                self.change_state(State::Failure);
                Ok(Event::Failure)
            }

            // The mix is finished at this point, it cannot be used anymore.
            (_, State::Success | State::Failure | State::Error { .. }) => Err(Error::Dead),

            // The coordinator sent an error message. We can wrap up the mix, there's nothing else to do.
            (CoordinatorResponse::Error { code, message }, _) => {
                self.change_state(State::Error {
                    message: message.clone(),
                });

                let error = if message.contains("Banned") {
                    CoordinatorError::Banned
                } else if message.contains("Input is not confirmed") {
                    CoordinatorError::Unconfirmed
                } else {
                    CoordinatorError::Other(message)
                };

                Err(Error::Coordinator { code, error })
            }

            (response, _state) => Err(Error::InvalidStateMachine(response)),
        }
    }

    fn change_state(&mut self, new_state: State) {
        self.state = new_state;
    }

    fn verify_mix_id(&self, received_id: &str) -> Result<(), Error> {
        match &self.id {
            Some(id) if id != received_id => Err(Error::MixIdMismatch {
                expected: id.clone(),
                actual: received_id.to_owned(),
            }),
            _ => Ok(()),
        }
    }
}

/// Per wallet/seed unique pre-hash to ensure that the user does not mix with himself from
/// multiple devices.
pub struct PreUserHash(pub Vec<u8>);

impl From<Vec<u8>> for PreUserHash {
    fn from(value: Vec<u8>) -> Self {
        PreUserHash(value)
    }
}

impl std::fmt::Debug for PreUserHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PreUserHash")
            .field(&self.0.to_hex())
            .finish()
    }
}

/// Random bytes used for registration purposes.
#[derive(Debug, Clone)]
pub struct Bordereau([u8; 30]);

impl Bordereau {
    pub fn new() -> Self {
        use rand::Rng;
        let mut bordereau = [0_u8; 30];
        rand::thread_rng().fill(&mut bordereau);
        Self(bordereau)
    }
}

impl AsRef<[u8]> for Bordereau {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Internal mix state.
#[derive(Debug)]
enum State {
    Connect,
    Subscribe,
    RegisterInput,
    ConfirmInput {
        blinding_secret: blind_rsa_signatures::Secret,
        public_key: blind_rsa_signatures::PublicKey,
        bordereau: Bordereau,
    },
    ConfirmedInputWait {
        signature: blind_rsa_signatures::Signature,
        bordereau: Bordereau,
    },
    RegisterOutput {
        inputs_hash: String,
    },
    RevealOutput,
    Sign(bitcoin::Txid),
    Success,
    Failure,
    Error {
        #[allow(dead_code)]
        message: String,
    },
}

/// Coordinator generated event to be consumed by the local `Mix` state machine.
#[derive(Debug)]
pub enum CoordinatorResponse {
    Connected,
    SubscribedPool {
        network: bitcoin::Network,
        denomination: u64,
        min_amount: u64,
        cap_amount: u64,
        max_amount: u64,
    },
    ConfirmInputNotification {
        mix_id: String,
        public_key: blind_rsa_signatures::PublicKey,
    },
    ConfirmedInput {
        mix_id: String,
        blind_signature: blind_rsa_signatures::BlindSignature,
    },
    RegisterOutputNotification {
        mix_id: String,
        inputs_hash: String,
    },
    SigningNotification {
        mix_id: String,
        transaction: bitcoin::Transaction,
    },
    MixSuccessful {
        mix_id: String,
    },
    RevealNotification {
        mix_id: String,
    },
    MixFailed {
        mix_id: String,
    },
    Error {
        code: u32,
        message: String,
    },
}

/// Request to be sent to the coordinator through a normal stream.
#[derive(Debug)]
pub enum StreamRequest {
    Connect,
    SubscribePool {
        pool_id: String,
    },
    RegisterInput {
        pool_id: String,
        utxo: OutPoint,
        signature: String,
        remixer: bool,
        block_height: u32,
    },
    ConfirmInput {
        mix_id: String,
        blinded_destination: blind_rsa_signatures::BlindedMessage,
        user_hash: String,
    },
    Sign {
        mix_id: String,
        witness: Witness,
    },
    Reveal {
        mix_id: String,
        destination: Address,
    },
}

/// Request to be sent to the coordinator through an alternate identity.
#[derive(Debug)]
pub enum AlternateIdentityRequest {
    CheckOutput {
        receive_address: Address,
        signature: String,
    },
    RegisterOutput {
        inputs_hash: String,
        unblinded_signature: blind_rsa_signatures::Signature,
        destination: Address,
        bordereau: Bordereau,
    },
}

/// Event variants produced by the `Mix` state machine.
#[derive(Debug)]
pub enum Event {
    /// Wait for the coordinator to send the next message.
    WaitForCoordinator,
    /// Send a request to the coordinator through a normal stream.
    StandardRequest(StreamRequest),
    /// Send a request to the coordinator through an alternate identity.
    AltIdRequest(AlternateIdentityRequest),
    /// The mix has completed successfully.
    Success(bitcoin::Txid),
    /// The mix has failed according to the coordinator.
    Failure,
}

#[derive(Debug)]
pub enum Error {
    InvalidStateMachine(CoordinatorResponse),
    Blinding(blind_rsa_signatures::Error),
    Signing(Box<dyn std::error::Error + Send + Sync>),
    MixIdMismatch {
        expected: String,
        actual: String,
    },
    TransactionOutputsHashMismatch,
    MixTransaction(MixTxError),
    NetworkMismatch {
        expected: bitcoin::Network,
        actual: bitcoin::Network,
    },
    Dead,
    Coordinator {
        code: u32,
        error: CoordinatorError,
    },
}

#[derive(Debug)]
pub enum CoordinatorError {
    Banned,
    Unconfirmed,
    Other(String),
}

impl From<blind_rsa_signatures::Error> for Error {
    fn from(error: blind_rsa_signatures::Error) -> Self {
        Error::Blinding(error)
    }
}

fn blinding_options() -> blind_rsa_signatures::Options {
    blind_rsa_signatures::Options::new(blind_rsa_signatures::Hash::Sha256, false, 32)
}

/// Verifies that the mix transaction includes our input and output and that its structure
/// adheres to the Whirlpool protocol. The return value is a tuple of the indices of our
/// input and output in the transaction.
fn verify_mix_tx(
    tx: &bitcoin::Transaction,
    destination: &Address,
    input: &Input,
    denomination: u64,
    inputs_hash: &str,
) -> Result<(usize, usize), MixTxError> {
    // 1. verify that the inputs hash matches
    let input_refs: Vec<_> = tx.input.iter().map(|txin| txin.previous_output).collect();
    if !verify_inputs_hash(&input_refs, &inputs_hash) {
        return Err(MixTxError::InputsHashMismatch);
    }

    // 2. verify that our output is present
    let out_idx = tx
        .output
        .iter()
        .enumerate()
        .find_map(|(i, out)| (out.script_pubkey == destination.script_pubkey()).then_some(i))
        .ok_or(MixTxError::OutputNotFound)?;

    // 3. verify that our input is present
    let in_idx = tx
        .input
        .iter()
        .enumerate()
        .find_map(|(i, txin)| (txin.previous_output == input.outpoint).then_some(i))
        .ok_or(MixTxError::InputNotFound)?;

    // 4. verify that the input-output count matches
    if tx.input.len() != tx.output.len() {
        return Err(MixTxError::InputOutputCountMismatch);
    }

    // 5. verify that the transaction is not using sibling inputs
    let input_tx_hashes: HashSet<_> = tx
        .input
        .iter()
        .map(|txin| txin.previous_output.txid)
        .collect();
    if input_tx_hashes.len() < tx.input.len() {
        return Err(MixTxError::DuplicateInputHashes);
    }

    // 6. verify that the denomination matches
    for out in &tx.output {
        if out.value != denomination {
            return Err(MixTxError::DenominationMismatch);
        }
    }

    // 7. verify that no duplicate output addresses are present
    let output_scripts: HashSet<_> = tx
        .output
        .iter()
        .map(|out| out.script_pubkey.as_bytes())
        .collect();
    if output_scripts.len() < tx.output.len() {
        return Err(MixTxError::AddressReuse);
    }

    Ok((in_idx, out_idx))
}

fn verify_inputs_hash(outpoints: &[OutPoint], inputs_hash: &str) -> bool {
    let mut values: Vec<_> = outpoints
        .iter()
        .map(|out| format!("{}{}", out.txid, out.vout))
        .collect();

    values.sort();

    let preimage = values.join(";");

    use bitcoin::hashes::Hash;

    let hash = bitcoin::hashes::sha512::Hash::hash(preimage.as_bytes());
    hash.to_hex() == inputs_hash
}

#[derive(Debug)]
pub enum MixTxError {
    InputsHashMismatch,
    OutputNotFound,
    InputNotFound,
    DuplicateInputHashes,
    DenominationMismatch,
    InputOutputCountMismatch,
    TxAlreadySigned,
    AddressReuse,
    SignatureEmpty,
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use bitcoin::util::psbt;
    use bitcoin::{Address, Script, Transaction, TxIn, TxOut};
    use bitcoin::{PackedLockTime, Witness};

    #[derive(Debug)]
    struct MockSigner;

    impl Signer for MockSigner {
        fn sign_tx(
            &mut self,
            mut tx: psbt::PartiallySignedTransaction,
        ) -> Result<bitcoin::Transaction, Box<dyn std::error::Error + Send + Sync>> {
            for input in &mut tx.inputs {
                if input.witness_utxo.is_some() {
                    input.final_script_witness = Some(Witness::from_vec(vec![vec![0x00]]));
                    break;
                }
            }
            Ok(tx.extract_tx())
        }

        fn sign_message(
            &mut self,
            _: &Input,
            _: &str,
        ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
            Ok("fake sig".to_string())
        }
    }

    #[test]
    fn state_machine_flow_normal() {
        let (mut mix, request) = Mix::new(Params {
            input: input(),
            signer: signer(),
            destination: output_template(),
            pool_id: POOL_ID.to_owned(),
            denomination: 1_000_000,
            network: bitcoin::Network::Testnet,
            pre_user_hash: PreUserHash(vec![]),
            block_height: 500_000,
        });

        // client connects
        assert!(matches!(request, StreamRequest::Connect));

        // coordinator responds with a connected message and client responds with a subscribe request
        let connected = CoordinatorResponse::Connected;
        let request = mix.process(connected);
        assert!(matches!(
            request,
            Ok(Event::StandardRequest(StreamRequest::SubscribePool { .. }))
        ));

        // coordinator responds with a subscription and client registers an input
        let subscribe_pool_response = CoordinatorResponse::SubscribedPool {
            network: bitcoin::Network::Testnet,
            denomination: 1_000_000,
            min_amount: 1_000_170,
            cap_amount: 1_009_690,
            max_amount: 1_019_125,
        };
        let request = mix.process(subscribe_pool_response);
        assert!(matches!(
            request,
            Ok(Event::StandardRequest(StreamRequest::RegisterInput { .. }))
        ));

        // coordinator sends a confirm input notification and client responds with a confirmation attempt
        let confirm_inputs_notification = CoordinatorResponse::ConfirmInputNotification {
            mix_id: "000000".to_string(),
            public_key: rsa_keys().1,
        };
        let request = mix.process(confirm_inputs_notification);
        assert!(matches!(
            request,
            Ok(Event::StandardRequest(StreamRequest::ConfirmInput { .. }))
        ));

        // the coordinator requeued us into a different mix and sent a NEW confirm input notification
        let confirm_inputs_notification = CoordinatorResponse::ConfirmInputNotification {
            mix_id: MIX_ID.to_string(),
            public_key: rsa_keys().1,
        };
        let request = mix.process(confirm_inputs_notification);
        assert!(matches!(
            request,
            Ok(Event::StandardRequest(StreamRequest::ConfirmInput { .. }))
        ));

        let blinded_destination = if let Ok(Event::StandardRequest(StreamRequest::ConfirmInput {
            blinded_destination,
            ..
        })) = request
        {
            blinded_destination
        } else {
            unreachable!();
        };

        // coordinator responds with input confirmation acceptance
        let confirm_input_response = CoordinatorResponse::ConfirmedInput {
            blind_signature: server_rsa_sign(blinded_destination),
            mix_id: MIX_ID.to_string(),
        };
        let request = mix.process(confirm_input_response);
        assert!(matches!(request, Ok(Event::WaitForCoordinator)));

        // coordinator sends a register output notification and client responds with an output registration attempt
        let register_output_notification = CoordinatorResponse::RegisterOutputNotification {
            mix_id: MIX_ID.to_string(),
            inputs_hash: INPUTS_HASH.to_owned(),
        };
        let request = mix.process(register_output_notification);
        assert!(matches!(
            request,
            Ok(Event::AltIdRequest(
                AlternateIdentityRequest::RegisterOutput { .. }
            ))
        ));

        // coordinator tells client to sign and client responds with a signature
        let signing_notification = CoordinatorResponse::SigningNotification {
            mix_id: MIX_ID.to_string(),
            transaction: transaction(),
        };
        let request = mix.process(signing_notification);
        assert!(matches! { request, Ok(Event::StandardRequest(StreamRequest::Sign {..})) });

        // coordinator signals mix completion
        let mix_success_notification = CoordinatorResponse::MixSuccessful {
            mix_id: MIX_ID.to_string(),
        };
        let request = mix.process(mix_success_notification);
        assert!(matches!(mix.state, State::Success));
        assert!(matches!(request, Ok(Event::Success(_))));
    }

    #[test]
    fn state_machine_flow_failure() {
        let (mut mix, request) = Mix::new(Params {
            input: input(),
            signer: signer(),
            destination: output_template(),
            pool_id: POOL_ID.to_owned(),
            denomination: 1_000_000,
            network: bitcoin::Network::Testnet,
            pre_user_hash: PreUserHash(vec![]),
            block_height: 500_000,
        });

        // client connects
        assert!(matches!(request, StreamRequest::Connect));

        // coordinator responds with a connected message and client responds with a subscribe request
        let connected = CoordinatorResponse::Connected;
        let request = mix.process(connected);
        assert!(matches!(
            request,
            Ok(Event::StandardRequest(StreamRequest::SubscribePool { .. }))
        ));

        // coordinator responds with a subscription and client registers an input
        let subscribe_pool_response = CoordinatorResponse::SubscribedPool {
            network: bitcoin::Network::Testnet,
            denomination: 1_000_000,
            min_amount: 1_000_170,
            cap_amount: 1_009_690,
            max_amount: 1_019_125,
        };
        let request = mix.process(subscribe_pool_response);
        assert!(matches!(
            request,
            Ok(Event::StandardRequest(StreamRequest::RegisterInput { .. }))
        ));

        // coordinator sends a confirm input notification and client responds with a confirmation attempt
        let confirm_inputs_notification = CoordinatorResponse::ConfirmInputNotification {
            mix_id: MIX_ID.to_string(),
            public_key: rsa_keys().1,
        };
        let request = mix.process(confirm_inputs_notification);
        assert!(matches!(
            request,
            Ok(Event::StandardRequest(StreamRequest::ConfirmInput { .. }))
        ));

        let blinded_destination = if let Ok(Event::StandardRequest(StreamRequest::ConfirmInput {
            blinded_destination,
            ..
        })) = request
        {
            blinded_destination
        } else {
            unreachable!();
        };

        // coordinator responds with input confirmation acceptance
        let confirm_input_response = CoordinatorResponse::ConfirmedInput {
            blind_signature: server_rsa_sign(blinded_destination),
            mix_id: MIX_ID.to_string(),
        };
        let request = mix.process(confirm_input_response);
        assert!(matches!(request, Ok(Event::WaitForCoordinator)));

        // coordinator sends a register output notification and client responds with an output registration attempt
        let register_output_notification = CoordinatorResponse::RegisterOutputNotification {
            mix_id: MIX_ID.to_string(),
            inputs_hash: INPUTS_HASH.to_owned(),
        };
        let request = mix.process(register_output_notification);
        assert!(matches!(
            request,
            Ok(Event::AltIdRequest(
                AlternateIdentityRequest::RegisterOutput { .. }
            ))
        ));

        // coordinator tells client to sign and client responds with a signature
        let reveal_notification = CoordinatorResponse::RevealNotification {
            mix_id: MIX_ID.to_string(),
        };
        let request = mix.process(reveal_notification);
        assert!(matches! { request, Ok(Event::StandardRequest(StreamRequest::Reveal {..})) });

        // coordinator signals mix failure
        let mix_failed_notification = CoordinatorResponse::MixFailed {
            mix_id: MIX_ID.to_string(),
        };
        let request = mix.process(mix_failed_notification);
        assert!(matches!(mix.state, State::Failure));
        assert!(matches!(request, Ok(Event::Failure)));
    }

    #[test]
    fn inputs_hash() {
        let outpoints = vec![
            OutPoint::from_str(
                "1a1ff49a285a4b2131e7155e25341d575e7e6e9278c5f00bbc90dec362412334:1",
            )
            .unwrap(),
            OutPoint::from_str(
                "d1d42d8ffdc8f1cc93d2eb184acfb0c19c56ca501a4a2fa8753deaa1dfa8d751:5",
            )
            .unwrap(),
            OutPoint::from_str(
                "4894aaa78aaf1460098befa81d111b1f2702f71f3134a0365f921d4fc72ffc20:55",
            )
            .unwrap(),
        ];

        let valid = super::verify_inputs_hash(&outpoints, "fc4a986b472b76f00873e0d2a735a9e3fd4c01e3953bc76e150e0559c170368e508c83fcda69831a620e4712540fc734b0b65d5d66d734a24182ff6a932ba736");
        assert!(valid);
    }

    fn input() -> Input {
        Input {
            outpoint: OutPoint::from_str(
                "5e2383defe7efcbdc9fdd6dba55da148b206617bbb49e6bb93fce7bfbb459d44:1",
            )
            .unwrap(),
            prev_txout: TxOut {
                value: 1_000_200,
                script_pubkey: Script::new(),
            },
            fields: psbt::Input {
                // just use this to mark our own input so our fake signer can find it
                witness_utxo: Some(TxOut::default()),
                ..Default::default()
            },
        }
    }

    fn signer() -> Box<dyn Signer> {
        Box::new(MockSigner)
    }

    fn transaction() -> Transaction {
        // valid unsigned 2-in 2-out mix transaction where we are one participant
        Transaction {
            lock_time: PackedLockTime::ZERO,
            version: 2,
            input: vec![
                // us
                TxIn {
                    previous_output: input().outpoint,
                    script_sig: Script::default(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: Witness::new(),
                },
                // other
                TxIn {
                    previous_output: OutPoint::from_str(
                        "35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055:0",
                    )
                    .unwrap(),
                    script_sig: Script::default(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![
                // us
                TxOut {
                    value: 1_000_000,
                    script_pubkey: output_template().address.script_pubkey(),
                },
                // other
                TxOut {
                    value: 1_000_000,
                    script_pubkey: Address::from_str("tb1q765gfuv0f4l83fqk0sl9vaeu8tjcuqtyrrduyv")
                        .unwrap()
                        .script_pubkey(),
                },
            ],
        }
    }

    fn output_template() -> OutputTemplate {
        OutputTemplate {
            address: Address::from_str("tb1qjara0278vrsr8gvaga7jpy2c9amtgvytr44xym").unwrap(),
            fields: psbt::Output::default(),
        }
    }

    fn server_rsa_sign(
        blinded: blind_rsa_signatures::BlindedMessage,
    ) -> blind_rsa_signatures::BlindSignature {
        let (sk, _) = rsa_keys();
        sk.blind_sign(blinded, &blinding_options()).unwrap()
    }

    fn rsa_keys() -> (
        blind_rsa_signatures::SecretKey,
        blind_rsa_signatures::PublicKey,
    ) {
        let sk = blind_rsa_signatures::SecretKey::from_pem(RSA_PRIVATE_KEY).unwrap();
        let pk = sk.public_key().unwrap();
        (sk, pk)
    }

    const POOL_ID: &str = "0.01btc";
    const MIX_ID: &str = "123456";
    const INPUTS_HASH: &str = "b4cf97318da7536fb2e49f6104afa1526d6e69940d45d35f12c5bdc51b4cbac3604dbb4317771586c4b1e12c71e685e7061a320379cefa75663ca481ae8c93c8";

    const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDQYZx+lzl2SCg/
pjOkqAcrBT4/KWTxkCU3q5E2/B7gm9YleOc9pZec0Vkk6LaHtlZLGqVFygLy/3/0
69U+j5yMcrD0dQP5jCCWV7RhMNYdpwai0X9Bw9AFbTSxbKKHmgZ/baBJMpCUvas5
QDhXbZPMph4/L9gCAVmHCazeyHITMIXhRZRSEYaqWme2LzsyiVMrFJhQZGcMXBiF
JDpUCJb5UsCfqPUMEqPya2B4jbawwXTeX5GJueh5Ewq1wRll5Oipc9E5pI7r16ht
xkPVxS94P/pLW3weCstw7vwouN7SUs0dUQ803YYXWczYMbXV6ahqlrJDmILko+dn
J0lMd4h9AgMBAAECggEAGCDdUoknJauIQYp4m127ar9SLFUaM6BZtt7+UwwRdTeG
LdOYjvpQGl/hPxVVIVS7HDorHfActE9iXRU7nWFaoqabF8s+2RPhKBdiswhJGqje
61Zvskk+mopBGjQ2g5YRn4qtjxw0QozNuTTW8USmYwFvKijbjavjVnAH3Mn/73mu
y6MpRvtPxs7nVJ4BAonOWio4SRPYZD8qLCtQK1t0k7J7CRD49+L/cIRgVYGcCQR2
hsohDQMHYc8I4O4mJZYUMsQMxYvYBf83T6dW2KACZaX2lFGX6WK8ZCcvQHob2V/c
0vbu+HYwz+i0KyEvr8HRHeQCkxrDm9n0OYbHPhRC7wKBgQDaJa3YXSbrEktKPhCh
mydo/YXYbRZLY5lJb3O8GMQDxt8sPNPj69nmfQwxF6JRwtsjkG6/roR/wDa6OHmZ
/vZ9zUtsSyHiVIxTuV4uJsQothTIEfFl8pT8GbwvgDVosfQQYvyEf5d8K3m8tc+Z
66iGBgQJQhq0cEdQvpd8kCsgAwKBgQD0ih8VO3QwNerHDj88CsNlf4gn7yzuMqbl
ThQRckkunDn4BYUyj+/lB4k5ZuR+dm0jmf3Y0V9C4GsCG0+os/VKMVBnK/0ywvCJ
9dBtiAtu1+HQd4Pi5JPTMK/kmtas4Rv8PYSZkm++P/W37BdboEGLHfGgSAmMLX+n
W6l/N3uNfwKBgGy9M3cSl/+9UsJjRa8IxBBVr44+ckqKDzLH14z/W1X2n/BRMd3/
BtMZqiYefc77rnh/2nS57Vow2hbhZ9wXd48l8l685NsJAhoJ4KRotocEnD9OkmIb
FaDEw0V6RyU070/rx6vUXhKLKVej2SQEkDCedwyWYvFmtmXNW32/7385AoGACzs0
xkLeyUAQsmfDG7za0JSU6lCf3ajR5YI6hbqcBdoDB5MpVPMrb3dzJAHHyM8joBj4
gbbMC0RHZedfNz5cq7WsHbD1hhlR9uQlWIKBE+wyYOK8WfVpnK+FxJgf9/y2zlT8
/BivrSs+292qDPlFSWBsspHcbmXAkS0ykbc4o30CgYBGE/BcafdB4ISmni1Rkxow
VA0o5ll1xaCcaahI6b1DPiyedLxsju9gi2ba6owESaHjJm+JcGajd74Qr95BKIOL
FkZm1ej0JOi09aix+TrQ6pwqb8NTujAjuOW1ru/c503gF28wmZTBczRhsADph3Z+
VP02kJduyyYSjlaMP9MyUQ==
-----END PRIVATE KEY-----";
}
