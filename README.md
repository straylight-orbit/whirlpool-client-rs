## Samourai Whirlpool Client

A Samourai Whirlpool client written in pure Rust.

It includes a Tor-only client implementation that can be turned off by disabling the `client`
feature. In that case, alternative clients (such as those supporting the `async/await` paradigm
or I2P connectivity) may be written using the Whirlpool primitives that the library provides.

## Basic Usage

`client::API` provides an interface to the REST API. Exposes pool info, tx0 creation and tx0
broadcast functionality.

`client::start` starts a new mix using `mix::Params`. The supplied input must come either from
premix or postmix (i.e. must be a tx0 descendant). Optionally notifies the caller with mix progress
if the `notify` parameter is supplied and set up to do so.

Official Samourai partners can set their own partnership code by setting the `WPID` environment
variable at compile time.

## Donations

If you find this library useful, donations are greatly appreciated. Our donation address is
`bc1qdqyddz0fh8d24gkwhuu5apcf8uzk4nyxw2035a`

## Issues/Questions

Email address in `Cargo.toml`

PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEYcBg1RYJKwYBBAHaRw8BAQdAlidgYUg/BziI+qJrEeBYpcJHQkur3KLT
Ubmrq4NnVBnNQXN0cmF5bGlnaHRfb3JiaXRAcHJvdG9ubWFpbC5jb20gPHN0
cmF5bGlnaHRfb3JiaXRAcHJvdG9ubWFpbC5jb20+wo8EEBYKACAFAmHAYNUG
CwkHCAMCBBUICgIEFgIBAAIZAQIbAwIeAQAhCRAuw2tD1SBUPBYhBC3Fy4ua
0Z4tk+DZmS7Da0PVIFQ8+kMA/0sF1fSezjin1keftDfjuCEyYdHCQgWEuwSb
Qvlwm+OGAQDzgZ7xdub1eL5rVzEMuVdtC3qOxOwOa02vS48XHGDJBc44BGHA
YNUSCisGAQQBl1UBBQEBB0BRCat3z3/ayilbLPvN6g9dNli2n5lceU4EAURj
k3hZCgMBCAfCeAQYFggACQUCYcBg1QIbDAAhCRAuw2tD1SBUPBYhBC3Fy4ua
0Z4tk+DZmS7Da0PVIFQ87BoBAOV+4dVY5iyJ3TL2Yaqc/fwADW53avrDO3sd
yiJSUkVPAQC4lWifjKlVYUT3yPICSbv7mtdYAFzDCbZTptksBV+EBg==
=/C35
-----END PGP PUBLIC KEY BLOCK-----
```

## License

The library is licensed under GPLv3. See [COPYING](COPYING) for details.
