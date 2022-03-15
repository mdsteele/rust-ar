# rust-ar

[![Build Status](https://github.com/mdsteele/rust-ar/actions/workflows/tests.yml/badge.svg)](https://github.com/mdsteele/rust-ar/actions/workflows/tests.yml)
[![Crates.io](https://img.shields.io/crates/v/ar.svg)](https://crates.io/crates/ar)
[![Documentation](https://docs.rs/ar/badge.svg)](https://docs.rs/ar)

A rust library for encoding/decoding Unix archive (.a) files.

Documentation: https://docs.rs/ar

## Overview

The `ar` crate is a pure Rust implementation of a
[Unix archive file](https://en.wikipedia.org/wiki/Ar_(Unix)) reader and writer.
This library provides a streaming interface, similar to that of the
[`tar`](https://crates.io/crates/tar) crate, that avoids having to ever load a
full archive entry into memory.

## License

rust-ar is made available under the
[MIT License](http://spdx.org/licenses/MIT.html).
