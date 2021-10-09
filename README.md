# QUC-test

A simple file transfer client/server over QUIC. This is **not** secure and **not** production ready. I made this in a couple hours one evenning to try using [quinn](https://crates.io/crates/quinn) and [tokio](https://tokio.rs). It has simple logging/tracing, self-signed certificates, multiple concurrent transfers and multi-socket for higher performance.

## Performance

In fairly simplistic and un-scientific tests ran on a [AMD 2950x](https://www.amd.com/en/products/cpu/amd-ryzen-threadripper-2950x), I managed to reach ~700 MiB/s very quickly. This was mostly to test the performance of *quinn* itself. And I was happily surprised to see ~200 MiB/s on a single socket with fairly low CPU usage.

## Usage

Both the server and the client have detailed usage information when running them with `--help`.

## Security

There is none, QUIC is an encrypted protocol but that's the only security you will find here.
