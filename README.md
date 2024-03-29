# Samourai Whirlpool Client

A Samourai Whirlpool client written in Rust.

Changes are tracked in [CHANGELOG](CHANGELOG.md).

## ⚠️  IMPORTANT ⚠️

### Tor Usage

**DO NOT USE WITHOUT TOR.** The only way to defend against a malicious or hacked coordinator is to
connect through Tor. If you fork this library and disable Tor, you are placing yourself or your
users at risk.

Even if you fully trust the coordinator, if you connect to it directly and your internet connection
is monitored, you will be exposed as a Whirlpool user.

### PGP Signatures

All commits and releases starting from `v2.0.0` are signed by Straylight using
[these keys](signing_key.gpg.asc) ([mirror](https://github.com/straylight-orbit.gpg)). Used strictly
for signing, not email encryption.

If you are not using Straylight's version, you are not using the original version of this library so
be sure to audit the code extra carefully.

## Basic Usage

`client::API` provides an interface to the REST API. Exposes pool info, tx0 creation and tx0
broadcast functionality. An API instance reuses a single Tor circuit. To get a fresh circuit,
build a new API instance.

`client::start` starts a new mix using `mix::Params`. The supplied input must come either from
premix or postmix (i.e. must be a tx0 descendant). Optionally notifies the caller with mix progress
if the `notify` parameter is supplied and set up to do so. Each mix runs on a fresh Tor circuit.

Official Samourai partners can set their own partnership code by setting the `WPID` environment
variable at compile time (`WPID=partnerid cargo build`).

## Features

The crate exposes the following feature flags:

* `rustls-webpki` *(default)* - Rust TLS implementation using the webpki embedded certificate store
* `rustls-native-certs` - Rust TLS implementation using the platform's native certificate store

These should be used in a mutually exclusive (not additive) fashion.

## License

The library is licensed under GPLv3. See [COPYING](COPYING) for details.

