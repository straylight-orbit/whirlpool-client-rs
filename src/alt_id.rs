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

//! This module contains functionality for converting alternate identity requests into HTTP requests.
//! Care must be taken to never send these requests through the same identity as the one responsible
//! for mix coordination.

use crate::{endpoints::Endpoints, http, mix::AlternateIdentityRequest};
use serde::Deserialize;

/// Response payload returned by alternate identity (output related) endpoints.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AltIdResponse {
    Error { message: String },
    Ok {},
}

impl AlternateIdentityRequest {
    pub fn into_request(self, endpoints: &Endpoints) -> http::Request<AltIdResponse> {
        let url = match &self {
            AlternateIdentityRequest::CheckOutput { .. } => endpoints.check_output.clone(),
            AlternateIdentityRequest::RegisterOutput { .. } => endpoints.register_output.clone(),
        };
        let body: Vec<u8> = self.try_into().unwrap();

        http::Request {
            url,
            method: http::Method::POST,
            body: Some(http::Body {
                body,
                content_type: "application/json",
            }),
            alt_id: true,
            de_type: std::marker::PhantomData,
        }
    }
}
