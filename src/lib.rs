#![feature(const_trait_impl, exclusive_range_pattern)]

use std::{
    error::Error,
    fmt::{Debug, Display},
};

use tracing::{warn, Level};

pub const QUIC_PROTO: &[u8] = b"qt-01";

pub fn setup_logging(verbose: u8) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let level = match verbose {
        0 => Level::ERROR,
        1 => Level::WARN,
        2 => Level::INFO,
        3 => Level::DEBUG,
        _ => Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_level(true)
        .with_max_level(level)
        .with_thread_names(true)
        .try_init()?;

    if level > Level::WARN {
        warn!("Running with high verbosity can degrate performance");
    }

    Ok(())
}

/// Wrapper around a [`usize`] that allows pretty printing of byte sizes
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Size(pub usize);

impl Debug for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (divider, unit) = bytes_of(self.0 as u64);

        f.debug_tuple("Size")
            .field(&format!("{:.3} {}", self.0 as f64 / divider as f64, unit))
            .finish()
    }
}

impl Display for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (divider, unit) = bytes_of(self.0 as u64);

        f.write_str(&format!("{:.3} {}", self.0 as f64 / divider as f64, unit))
    }
}

impl const From<usize> for Size {
    fn from(size: usize) -> Self {
        Self(size)
    }
}

impl const Into<usize> for Size {
    fn into(self) -> usize {
        self.0
    }
}

impl const From<u64> for Size {
    fn from(size: u64) -> Self {
        Self(size as _)
    }
}

impl const Into<u64> for Size {
    fn into(self) -> u64 {
        self.0 as _
    }
}

impl const From<u32> for Size {
    fn from(size: u32) -> Self {
        Self(size as _)
    }
}

impl const Into<u32> for Size {
    fn into(self) -> u32 {
        self.0 as _
    }
}

/// Memory size helper.
/// Returns a divider and a static string denoting the unit (B, KiB, etc.)
#[must_use]
pub const fn bytes_of(value: u64) -> (u64, &'static str) {
    match num_bits::<u64>() as u32 - value.leading_zeros() - 1 {
        0..10 => (1, "B"),
        10..20 => (1 << 10, "KiB"),
        20..30 => (1 << 20, "MiB"),
        30..40 => (1 << 30, "GiB"),
        40..50 => (1 << 40, "TiB"),
        50..60 => (1 << 50, "PiB"),
        _ => (1 << 60, "EiB"),
    }
}

/// Computes the number of bits in a number
#[must_use]
pub const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}
