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

const fn base(onion: bool, mainnet: bool) -> &'static str {
    if onion {
        if mainnet {
            "udkmfc5j6zvv3ysavbrwzhwji4hpyfe3apqa6yst7c7l32mygf65g4ad.onion:80"
        } else {
            "y5qvjlxvbohc73slq4j4qldoegyukvpp74mbsrjosnrsgg7w5fon6nyd.onion:80"
        }
    } else {
        if mainnet {
            "pool.whirl.mx:8080"
        } else {
            "pool.whirl.mx:8081"
        }
    }
}

/// Fully formatted server-side endpoints.
#[derive(Debug)]
pub struct Endpoints {
    pub server: &'static str,
    pub ws_connect: String,
    pub check_output: String,
    pub register_output: String,
    pub pools: String,
    pub tx0_data: String,
    pub tx0_push: String,
}

/// Returns fully-formatted `.onion` endpoints for either `mainnet` or `testnet`.
pub fn onion(mainnet: bool) -> Endpoints {
    let server = base(true, mainnet);

    Endpoints {
        server,
        ws_connect: format!("ws://{server}/ws/connect"),
        check_output: format!("http://{server}/rest/checkOutput"),
        register_output: format!("http://{server}/rest/registerOutput"),
        pools: format!("http://{server}/rest/pools"),
        tx0_data: format!("http://{server}/rest/tx0/v1"),
        tx0_push: format!("http://{server}/rest/tx0/push"),
    }
}

/// Returns fully-formatted clearnet endpoints for either `mainnet` or `testnet`.
pub fn clearnet(mainnet: bool) -> Endpoints {
    let server = base(false, mainnet);

    Endpoints {
        server,
        ws_connect: format!("wss://{server}/ws/connect"),
        check_output: format!("https://{server}/rest/checkOutput"),
        register_output: format!("https://{server}/rest/registerOutput"),
        pools: format!("https://{server}/rest/pools"),
        tx0_data: format!("https://{server}/rest/tx0/v1"),
        tx0_push: format!("https://{server}/rest/tx0/push"),
    }
}
