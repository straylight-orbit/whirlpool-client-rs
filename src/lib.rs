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

use bitcoin::psbt;

pub mod alt_id;
pub mod codec;
pub mod endpoints;
pub mod http;
pub mod mix;
pub mod pool;
pub mod tx0;
pub mod util;

pub use bitcoin;

const WP_VERSION: &str = "0.23";
const UA_HTTP: &str = "whirlpool-client/0.23";

/// Contains information about an own input for transaction building and signing purposes.
#[derive(Debug)]
pub struct Input {
    /// Outpoint used by this input.
    pub outpoint: bitcoin::OutPoint,
    /// Previous txout used by this input.
    pub prev_txout: bitcoin::TxOut,
    /// Arbitrary per-input PSBT fields for use by the signer.
    pub fields: psbt::Input,
}

/// Contains information about an own output for transaction building and signing purposes.
#[derive(Debug)]
pub struct OutputTemplate {
    /// Address that this output is sending to.
    pub address: bitcoin::Address,
    /// Arbitrary per-output PSBT fields for use by the signer.
    pub fields: psbt::Output,
}

/// A trait that enables implementing types to perform signing.
pub trait Signer: std::fmt::Debug + Send {
    /// Signs a PSBT and returns the finalized transaction.
    fn sign_tx(
        &mut self,
        tx: psbt::PartiallySignedTransaction,
    ) -> Result<bitcoin::Transaction, Box<dyn std::error::Error + Send + Sync>>;

    /// Signs a message for an input.
    fn sign_message(
        &mut self,
        input: &Input,
        message: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;
}

pub use client::{start, start_blocking, Info, TorConfig, API};
pub use mix::{Event, Params};
use pool::PoolId;

pub mod client {
    //! Contains a Tor-only Whirlpool client. The client can be started in the current thread or a
    //! new thread can be spawned. In the case of latter, communication with the caller is done
    //! through a crossbeam channel.
    use bitcoin::Network;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
    use std::thread;
    use std::time::Duration;
    use tungstenite::stream::MaybeTlsStream;
    use tungstenite::WebSocket;

    use crate::*;

    #[derive(Debug, Copy, Clone)]
    /// Tor configuration for the client.
    pub struct TorConfig {
        /// The IP address of the socks5 proxy.
        pub host: std::net::Ipv4Addr,
        /// The port of the socks5 proxy.
        pub port: u16,
        /// Forces the client to use an exit node and connect to the clearnet version of the
        /// coordinator instead of staying within the Tor network. Not recommended unless there
        /// are problems with the .onion version. This does not enable or disable Tor, it merely
        /// controls which endpoints are used.
        pub exit_into_clearnet: bool,
        /// Determines timeout for HTTP requests.
        pub request_timeout: Duration,
    }

    impl Default for TorConfig {
        fn default() -> Self {
            Self {
                host: Ipv4Addr::LOCALHOST,
                port: 9050,
                exit_into_clearnet: false,
                request_timeout: Duration::from_secs(120),
            }
        }
    }

    /// REST API where the coordinator can be asked for pool information and where tx0 transactions
    /// can be pushed. This is isolated from any mix circuits.
    pub struct API {
        agent: ureq::Agent,
        endpoints: endpoints::Endpoints,
    }

    impl API {
        /// Creates a new API instance with its own isolation tokens. Returns `None` if Tor is not
        /// locally running and available.
        pub fn new(tor_config: TorConfig, network: Network) -> Option<API> {
            if port_check::is_port_reachable((tor_config.host, tor_config.port)) {
                let agent = build_http_agent(tor_config);
                let endpoints = select_endpoints(tor_config.exit_into_clearnet, network);
                Some(Self { agent, endpoints })
            } else {
                None
            }
        }

        /// Fetches pool info from the coordinator.
        pub fn pools(&self) -> Result<Vec<pool::Pool>, HttpError> {
            let request = pool::Pool::request(&self.endpoints);
            let response = http_request(&self.agent, request)?;
            Ok(response.pools)
        }

        /// Fetches TX0 data from the coordinator. Needed to craft a TX0.
        pub fn tx0_data(&self, scode: Option<String>) -> Result<Vec<tx0::Tx0Data>, HttpError> {
            let request = tx0::Tx0Data::request(&self.endpoints, scode);
            let response = http_request(&self.agent, request)?;

            Ok(response.tx0_datas)
        }

        /// Pushes a TX0 to the coordinator.
        pub fn tx0_push(
            &self,
            tx: &bitcoin::Transaction,
            pool_id: &PoolId,
        ) -> Result<tx0::Tx0PushResponse, HttpError> {
            let request = tx0::push_tx0_request(&self.endpoints, tx, pool_id);
            http_request(&self.agent, request)
        }

        /// Fetches Tor Project's homepage and checks that the HTTP status equals 200. Useful for
        /// testing basic connectivity. Debug-only.
        #[cfg(debug_assertions)]
        #[allow(clippy::result_large_err)]
        pub fn tor_check(&self, onion: bool) -> Result<(), ureq::Error> {
            let start_instant = std::time::Instant::now();
            let path = match onion {
                true => "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
                false => "https://www.torproject.org/",
            };
            self.agent.get(path).call()?;
            let duration = std::time::Instant::now() - start_instant;
            log::debug!(
                "tor_check (onion: {}) took {} seconds",
                onion,
                duration.as_secs()
            );
            Ok(())
        }
    }

    /// Builds a new HTTP agent with new isolation tokens.
    fn build_http_agent(tor_config: TorConfig) -> ureq::Agent {
        let TorConfig {
            host: proxy_host,
            port: proxy_port,
            request_timeout,
            ..
        } = tor_config;

        let (username, password) = isolation_tokens();

        let proxy = ureq::Proxy::new(format!(
            "socks5://{username}:{password}@{proxy_host}:{proxy_port}"
        ))
        .expect("format proxy URL properly");

        ureq::builder()
            .proxy(proxy)
            .user_agent(UA_HTTP)
            .timeout_connect(request_timeout)
            .build()
    }

    /// Selects endpoints based on routing preference and Bitcoin network.
    fn select_endpoints(exit_into_clearnet: bool, network: Network) -> endpoints::Endpoints {
        match exit_into_clearnet {
            true => endpoints::clearnet(network == Network::Bitcoin),
            false => endpoints::onion(network == Network::Bitcoin),
        }
    }

    /// Starts a new Whirlpool mix in a separate thread. The `notify` parameter function may be used to handle
    /// notification events in a custom manner (e.g. logging, channel notifications...)
    ///
    /// Returns `Ok(txid)` if the mix comples successfully. Mixes occasionally fail on the coordinator side due to
    /// other participants, in which case `Error::MixFailed` is returned. That variant does not indicate a problem
    /// and such a mix can be restarted. Other error variants imply networking issues or a programming error
    /// on either side.
    pub fn start<F: Fn(Info) + Send + 'static>(
        params: mix::Params,
        tor_config: TorConfig,
        notify: F,
    ) -> thread::JoinHandle<Result<bitcoin::Txid, Error>> {
        thread::spawn(move || start_blocking(params, tor_config, notify))
    }

    /// Starts a new Whirlpool mix in the current thread in a blocking manner. The `notify` parameter function
    /// may be used to handle notification events in a custom manner (e.g. logging, channel notifications...)
    ///
    /// Returns `Ok(txid)` if the mix comples successfully. Mixes occasionally fail on the coordinator side due to
    /// other participants, in which case `Error::MixFailed` is returned. That variant does not indicate a problem
    /// and such a mix can be restarted. Other error variants imply networking issues or a programming error
    /// on either side.
    pub fn start_blocking<F: Fn(Info)>(
        params: mix::Params,
        tor_config: TorConfig,
        notify: F,
    ) -> Result<bitcoin::Txid, Error> {
        log::info!("*** if you find this project useful, please consider donating: bc1qdqyddz0fh8d24gkwhuu5apcf8uzk4nyxw2035a ***");

        if !port_check::is_port_reachable((tor_config.host, tor_config.port)) {
            return Err(Error::TorMissing);
        }

        let alt_client = build_http_agent(tor_config);
        let endpoints = select_endpoints(tor_config.exit_into_clearnet, params.network);

        let (primary_username, primary_password) = isolation_tokens();

        let proxy_addr = SocketAddrV4::new(tor_config.host, tor_config.port);

        let socks_stream = socks::Socks5Stream::connect_with_password(
            proxy_addr,
            endpoints.server,
            &primary_username,
            &primary_password,
        )
        .map_err(NetworkError::Socks)?
        .into_inner();

        socks_stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .map_err(|_| NetworkError::CannotSetReadTimeout)?;

        let (mut ws, _) = tungstenite::client_tls(&endpoints.ws_connect, socks_stream)
            .map_err(|_| NetworkError::WsHandshake)?;

        let (mut mix, connect_request) = mix::Mix::new(params);

        send_ws(&mut ws, connect_request)?;

        loop {
            let response = read_ws(&mut ws)?;
            let response = match response {
                ServerMsg::Response(response) => response,
                ServerMsg::Ping | ServerMsg::Pong => continue,
                ServerMsg::Timeout => {
                    log::debug!("WS >>: PING");
                    ws.write_message(tungstenite::Message::Ping(Vec::new()))
                        .map_err(NetworkError::Tungstenite)?;
                    continue;
                }
            };

            let event = mix.process(response);

            let info = match &event {
                Ok(event) => (event, mix.must_stay()).into(),
                Err(_) => Info::Error,
            };
            notify(info);

            let event = event.map_err(Error::Mix)?;

            match event {
                mix::Event::WaitForCoordinator => {}
                mix::Event::StandardRequest(request) => send_ws(&mut ws, request)?,
                mix::Event::AltIdRequest(request) => {
                    let response = http_request(&alt_client, request.into_request(&endpoints))
                        .map_err(NetworkError::Http)?;
                    if let alt_id::AltIdResponse::Error { message } = response {
                        match message.as_str() {
                            "Output already registered" => break Err(Error::OutputReuse),
                            _ => break Err(Error::AltId(message)),
                        }
                    }
                }
                mix::Event::Success(txid) => break Ok(txid),
                mix::Event::Failure => break Err(Error::MixFailed),
            }
        }
    }

    /// Used to communicate status information when in a context where a mix handle
    /// cannot be accessed directly (such as in a multithreaded environment).
    #[derive(Debug)]
    pub enum Info {
        /// The mix is in progress.
        Working {
            /// The current mix step.
            step: Step,
            /// Whether the client must refrain from disconnecting for the time being because
            /// leaving would ruin the mix and get the UTXO banned by the coordinator.
            must_stay: bool,
        },
        /// The mix completed successfully with the contained txid.
        Success(bitcoin::Txid),
        /// The mix failed according to the coordinator. Not a user error, this is a normal
        /// path occasionally and does not imply that the client did anything wrong (most
        /// likely some other mix participant caused the mix to fail).
        Failure,
        /// The mix failed due to an unexpected error. This is not normal; it implies a programming
        /// or system error either on the client side or the coordinator side.
        Error,
    }

    /// Invidividual mix steps for informational purposes.
    #[derive(Debug)]
    pub enum Step {
        WaitingForCoordinator,
        Connecting,
        Subscribing,
        RegisteringInput,
        ConfirmingInput,
        CheckingOutput,
        RegisteringOutput,
        Signing,
        RevealingOutput,
    }

    #[derive(Debug)]
    pub enum Error {
        Mix(mix::Error),
        OutputReuse,
        MixFailed,
        CodecIn(String, codec::Error),
        CodecOut(codec::Error),
        AltId(String),
        TorMissing,
        Network(NetworkError),
    }

    #[derive(Debug)]
    pub enum NetworkError {
        CannotSetReadTimeout,
        Socks(std::io::Error),
        Http(HttpError),
        Tungstenite(tungstenite::Error),
        WsHandshake,
    }

    impl From<NetworkError> for Error {
        fn from(error: NetworkError) -> Self {
            Error::Network(error)
        }
    }

    #[derive(Debug)]
    pub enum HttpError {
        UnexpectedBody {
            error: serde_json::Error,
            status: u16,
            body: String,
        },
        Transport(Box<ureq::Transport>),
        Io(std::io::Error),
    }

    impl From<(&mix::Event, bool)> for Info {
        fn from((e, must_stay): (&mix::Event, bool)) -> Self {
            match e {
                mix::Event::WaitForCoordinator => Info::Working {
                    step: Step::WaitingForCoordinator,
                    must_stay,
                },
                mix::Event::StandardRequest(req) => match req {
                    mix::StreamRequest::Connect => Info::Working {
                        step: Step::Connecting,
                        must_stay,
                    },
                    mix::StreamRequest::SubscribePool { .. } => Info::Working {
                        step: Step::Subscribing,
                        must_stay,
                    },
                    mix::StreamRequest::RegisterInput { .. } => Info::Working {
                        step: Step::RegisteringInput,
                        must_stay,
                    },
                    mix::StreamRequest::ConfirmInput { .. } => Info::Working {
                        step: Step::ConfirmingInput,
                        must_stay,
                    },
                    mix::StreamRequest::Sign { .. } => Info::Working {
                        step: Step::Signing,
                        must_stay,
                    },
                    mix::StreamRequest::Reveal { .. } => Info::Working {
                        step: Step::RevealingOutput,
                        must_stay,
                    },
                },
                mix::Event::AltIdRequest(req) => match req {
                    mix::AlternateIdentityRequest::CheckOutput { .. } => Info::Working {
                        step: Step::CheckingOutput,
                        must_stay,
                    },
                    mix::AlternateIdentityRequest::RegisterOutput { .. } => Info::Working {
                        step: Step::RegisteringOutput,
                        must_stay,
                    },
                },
                Event::Success(txid) => Info::Success(*txid),
                Event::Failure => Info::Failure,
            }
        }
    }

    /// Sends a websocket message.
    fn send_ws(
        socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
        request: mix::StreamRequest,
    ) -> Result<(), Error> {
        log::debug!("WS >>: {:#?}", request);
        let data: Vec<_> = request.try_into().map_err(Error::CodecOut)?;
        Ok(socket
            .write_message(tungstenite::Message::Binary(data))
            .map_err(NetworkError::Tungstenite)?)
    }

    /// Reads a websocket message.
    fn read_ws(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) -> Result<ServerMsg, Error> {
        let msg = socket.read_message().map_err(NetworkError::Tungstenite);

        match &msg {
            Err(NetworkError::Tungstenite(tungstenite::Error::Io(err)))
                if err.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Ok(ServerMsg::Timeout);
            }
            _ => {}
        }

        let msg = msg?;
        if msg.is_pong() {
            log::debug!("WS <<: PONG");
        } else {
            log::debug!("WS (raw) <<: {:#?}", msg);
        }

        if msg.is_ping() {
            return Ok(ServerMsg::Ping);
        }
        if msg.is_pong() {
            return Ok(ServerMsg::Pong);
        }

        let bytes = msg.into_data();
        // capture the whole response as a String if we fail to decode, should never happen
        let response: mix::CoordinatorResponse = bytes
            .as_slice()
            .try_into()
            .map_err(|e| Error::CodecIn(String::from_utf8_lossy(&bytes).into(), e))?;
        log::debug!("WS (decoded) <<: {:#?}", response);
        Ok(ServerMsg::Response(response))
    }

    /// Executes an HTTP request.
    fn http_request<T: serde::de::DeserializeOwned>(
        client: &ureq::Agent,
        req_data: http::Request<T>,
    ) -> Result<T, HttpError> {
        let request = match req_data.method {
            http::Method::GET => client.get(&req_data.url),
            http::Method::POST => client.post(&req_data.url),
        };

        log::debug!("HTTP >>: {:#?}", request);

        let start = std::time::Instant::now();
        let response = match req_data.body {
            Some(body) => request
                .set("Content-Type", body.content_type)
                .send_bytes(&body.body),
            None => request.call(),
        };
        let req_secs = std::time::Instant::now()
            .saturating_duration_since(start)
            .as_secs();

        log::debug!("HTTP ({} s) <<: {:#?}", req_secs, response);

        match response {
            Ok(response) | Err(ureq::Error::Status(_, response)) => {
                use std::io::Read;
                let mut buf = vec![];
                let status = response.status();
                response
                    .into_reader()
                    .read_to_end(&mut buf)
                    .map_err(HttpError::Io)?;
                if log::log_enabled!(log::Level::Debug) {
                    log::debug!("HTTP (body) <<: {}", String::from_utf8_lossy(&buf));
                }
                if buf.is_empty() && status == 200 {
                    // serde doesn't allow empty strings to be deserialized to anything so we have
                    // to get around that problem by creating an empty JSON valid body
                    buf.extend_from_slice("{}".as_bytes());
                }
                // capture the whole response as a String if we fail to decode, should never happen
                serde_json::from_slice(&buf).map_err(|error| HttpError::UnexpectedBody {
                    error,
                    status,
                    body: String::from_utf8_lossy(&buf).to_string(),
                })
            }
            Err(ureq::Error::Transport(error)) => Err(HttpError::Transport(Box::new(error))),
        }
    }

    /// Generates isolation tokens for Tor SOCKS5 proxies. They are meant to be used as
    /// a username:password combination when handshaking with a proxy. That creates a new
    /// Tor ciruit every time.
    fn isolation_tokens() -> (String, String) {
        use rand::{distributions::Alphanumeric, Rng};
        let mut first: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();
        let second = first.split_off(12);
        (first, second)
    }

    #[derive(Debug)]
    enum ServerMsg {
        Response(mix::CoordinatorResponse),
        Ping,
        Pong,
        Timeout,
    }
}
