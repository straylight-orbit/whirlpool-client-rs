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

use std::str::Utf8Error;

#[derive(Debug)]
pub enum Error {
    MalformedFrame,
    HeaderNotFound(&'static str),
    IO(std::io::Error),
    Utf8(Utf8Error),
    WriteInnerBody,
}

/// Barebones zero-copy STOMP encoder.
pub mod encode {
    use std::io::Write;

    use super::Error;

    const LF: u8 = 10;

    pub fn connect<W>(writer: &mut W, host: &str) -> Result<(), Error>
    where
        W: Write,
    {
        frame(
            writer,
            "CONNECT",
            &[("host", host), ("accept-version", "1.2")],
            |_| Ok(()),
        )
    }

    pub fn subscribe<W>(
        writer: &mut W,
        id: &str,
        destination: &str,
        headers: &[(&str, &str)],
    ) -> Result<(), Error>
    where
        W: Write,
    {
        frame(
            writer,
            "SUBSCRIBE",
            &[headers, &[("id", id), ("destination", destination)]].concat(),
            |_| Ok(()),
        )
    }

    pub fn send<W, F>(
        writer: &mut W,
        destination: &str,
        headers: &[(&str, &str)],
        write_body: F,
    ) -> Result<(), Error>
    where
        W: Write,
        F: Fn(&mut W) -> Result<(), Error>,
    {
        frame(
            writer,
            "SEND",
            &[headers, &[("destination", destination)]].concat(),
            write_body,
        )
    }

    pub fn frame<W, F>(
        writer: &mut W,
        msg_name: &str,
        headers: &[(&str, &str)],
        write_body: F,
    ) -> Result<(), Error>
    where
        W: Write,
        F: Fn(&mut W) -> Result<(), Error>,
    {
        writer.write_all(msg_name.as_bytes())?;
        writer.write_all(&[LF])?;
        for (key, value) in headers {
            writer.write_fmt(format_args!("{}:{}", key, value))?;
            writer.write_all(&[LF])?;
        }
        writer.write_all(&[LF])?;

        write_body(writer)?;

        writer.write_all(&[0])?;
        Ok(())
    }
}

/// Barebones zero-copy STOMP decoder.
pub mod decode {
    use super::Error;
    use std::collections::HashMap;
    use std::str::from_utf8 as as_utf8;

    pub enum ServerFrame<'a> {
        Connected,
        Message {
            headers: HashMap<&'a str, &'a str>,
            body: &'a [u8],
        },
        Receipt(&'a str),
        Error(&'a str),
    }

    impl<'a> ServerFrame<'a> {
        pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
            let msg_type_len = data
                .iter()
                .position(|c| *c == 10)
                .ok_or(Error::MalformedFrame)?;
            let msg_type = as_utf8(data.get(0..msg_type_len).ok_or(Error::MalformedFrame)?)?;

            let (body_sep_i, _) = data
                .windows(2)
                .enumerate()
                .find(|(_, chunk)| chunk == &[10, 10])
                .ok_or(Error::MalformedFrame)?;

            let (header, body) = data.split_at(body_sep_i);
            let headers = parse_headers(&header[msg_type_len + 1..])?;

            match msg_type {
                "CONNECTED" => Ok(ServerFrame::Connected),
                "MESSAGE" => Ok(ServerFrame::Message {
                    headers,
                    body: &body[..body.len() - 1],
                }),
                "RECEIPT" => Ok(ServerFrame::Receipt(
                    headers
                        .get("receipt-id")
                        .ok_or(Error::HeaderNotFound("receipt-id"))?,
                )),
                "ERROR" => Ok(ServerFrame::Error(as_utf8(data)?)),
                _ => Err(Error::MalformedFrame),
            }
        }
    }

    fn parse_headers(data: &[u8]) -> Result<HashMap<&str, &str>, Error> {
        let lines = data
            .split(|c| *c == 10)
            .map(|line| line.split(|c| *c == b':'));

        let mut map = HashMap::new();
        for mut line in lines {
            map.insert(
                as_utf8(line.next().ok_or(Error::MalformedFrame)?)?,
                as_utf8(line.next().ok_or(Error::MalformedFrame)?)?,
            );
        }

        Ok(map)
    }
}

impl From<Utf8Error> for Error {
    fn from(error: Utf8Error) -> Self {
        Self::Utf8(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IO(error)
    }
}
