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

//! Contains datastructures and logic for describing HTTP requests without forcing a particular HTTP
//! library on the user of the crate. These can be used to construct actual HTTP requests using an
//! existing HTTP client.
use std::marker::PhantomData;

#[derive(Debug)]
pub struct Request<T: serde::de::DeserializeOwned> {
    pub url: String,
    pub method: Method,
    pub body: Option<Body>,
    pub alt_id: bool,
    pub de_type: PhantomData<T>,
}

#[derive(Debug)]
pub enum Method {
    GET,
    POST,
}

#[derive(Debug)]
pub struct Body {
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Body {
    pub fn json<T: serde::Serialize>(value: &T) -> Self {
        Body {
            body: serde_json::to_vec(value).expect("JSON serialization failure"),
            content_type: "application/json",
        }
    }
}
