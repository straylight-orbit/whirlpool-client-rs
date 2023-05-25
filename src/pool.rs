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

use serde::{self, Deserialize};

use crate::{endpoints::Endpoints, http};

/// Represents the unique identifier of a pool.
#[derive(Debug, Clone, Deserialize)]
pub struct PoolId(String);

#[cfg(test)]
impl From<&str> for PoolId {
    fn from(value: &str) -> Self {
        PoolId(value.to_owned())
    }
}

impl AsRef<str> for PoolId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PoolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information about a particular pool as returned by the coordinator.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pool {
    #[serde(rename = "poolId")]
    pub id: PoolId,
    pub denomination: u64,
    pub fee_value: u64,
    pub must_mix_balance_min: u64,
    pub must_mix_balance_cap: u64,
    pub min_anonymity_set: u16,
    pub min_must_mix: u16,
    pub tx0_max_outputs: u16,
    #[serde(rename = "nbRegistered")]
    pub n_registered: u32,
    pub mix_status: MixStatus,
    pub elapsed_time: u32,
    #[serde(rename = "nbConfirmed")]
    pub n_confirmed: u32,
}

#[derive(Deserialize)]
pub struct PoolsResponse {
    pub pools: Vec<Pool>,
}

impl From<PoolsResponse> for Vec<Pool> {
    fn from(response: PoolsResponse) -> Self {
        response.pools
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MixStatus {
    ConfirmInput,
    RegisterOutput,
    RevealOutput,
    Signing,
    Success,
    Fail,
}

impl Pool {
    /// Fetches a list of available pools.
    pub fn request(endpoints: &Endpoints) -> http::Request<PoolsResponse> {
        http::Request {
            url: endpoints.pools.clone(),
            method: http::Method::GET,
            body: None,
            alt_id: false,
            de_type: std::marker::PhantomData,
        }
    }
}
