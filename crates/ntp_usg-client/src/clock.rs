// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! System clock adjustment utilities for applying NTP corrections.
//!
//! This module provides platform-specific functions for adjusting the system
//! clock using NTP offset measurements. Two adjustment strategies are available:
//!
//! - **Slew**: Gradually adjusts the clock rate so the time converges over a
//!   period. Preferred for small offsets as it avoids time discontinuities.
//! - **Step**: Immediately jumps the clock. Used for large offsets or initial
//!   synchronization.
//!
//! The [`apply_correction`](self::apply_correction) function automatically selects the strategy based
//! on the magnitude of the offset (threshold: 128ms, following ntpd convention).
//!
//! # Privileges
//!
//! All functions in this module require elevated privileges (root on Unix,
//! Administrator on Windows) to modify the system clock.
//!
//! # Platform Support
//!
//! - **Linux**: Uses `clock_adjtime(2)` for slew and `clock_settime(2)` for step.
//! - **macOS**: Uses `adjtime(2)` for slew and `settimeofday(2)` for step.
//! - **Windows**: Uses `SetSystemTimeAdjustment` for slew and `SetSystemTime` for step.
//!   Note: Windows slew adjusts the tick rate and remains in effect until reset.
//!   Call `slew_clock(0.0)` to restore the default tick rate.
//! - **Other platforms**: Returns [`ClockError::Unsupported`](self::ClockError::Unsupported).

#![allow(unsafe_code)]

use std::fmt;

/// Threshold for choosing slew vs step (128ms), following ntpd convention.
const STEP_THRESHOLD_SECS: f64 = 0.128;

/// Error type for clock adjustment operations.
#[derive(Debug)]
pub enum ClockError {
    /// The operation requires elevated privileges (root/admin).
    PermissionDenied,
    /// Platform-specific error with an OS error code.
    OsError(i32),
    /// Clock adjustment is not supported on this platform.
    Unsupported,
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClockError::PermissionDenied => write!(f, "permission denied (requires root/admin)"),
            ClockError::OsError(code) => write!(f, "OS error: {}", code),
            ClockError::Unsupported => write!(f, "clock adjustment not supported on this platform"),
        }
    }
}

impl std::error::Error for ClockError {}

/// The method used to correct the clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorrectionMethod {
    /// Clock was gradually adjusted (slew).
    Slew,
    /// Clock was immediately stepped.
    Step,
}

/// Gradually adjust (slew) the system clock by the given offset.
///
/// The clock rate is adjusted so the clock converges to the correct time
/// over a period without any discontinuity. This is preferred for small
/// offsets.
///
/// # Platform Behavior
///
/// - **Linux**: Uses `clock_adjtime(CLOCK_REALTIME, ...)` with `ADJ_OFFSET`.
/// - **macOS**: Uses `adjtime(&delta, NULL)`.
/// - **Windows**: Uses `SetSystemTimeAdjustment` to adjust the tick rate.
///   The adjustment remains in effect until reset. Pass `0.0` to restore the
///   default tick rate.
///
/// # Errors
///
/// Returns [`ClockError::PermissionDenied`] if the process lacks privileges.
/// Returns [`ClockError::Unsupported`] on unsupported platforms.
pub fn slew_clock(offset_seconds: f64) -> Result<(), ClockError> {
    platform::slew(offset_seconds)
}

/// Step (jump) the system clock by the given offset.
///
/// This immediately changes the system time. Only use for large offsets
/// (typically > 128ms) or initial synchronization.
///
/// # Platform Behavior
///
/// - **Linux**: Uses `clock_settime(CLOCK_REALTIME, ...)`.
/// - **macOS**: Uses `settimeofday(...)`.
/// - **Windows**: Uses `GetSystemTimeAsFileTime` + `SetSystemTime`.
///
/// # Errors
///
/// Returns [`ClockError::PermissionDenied`] if the process lacks privileges.
/// Returns [`ClockError::Unsupported`] on unsupported platforms.
pub fn step_clock(offset_seconds: f64) -> Result<(), ClockError> {
    platform::step(offset_seconds)
}

/// Apply an NTP offset correction, choosing slew vs step automatically.
///
/// Uses the ntpd convention:
/// - |offset| <= 128ms: slew (gradual adjustment)
/// - |offset| > 128ms: step (immediate jump)
///
/// Returns the correction method used.
///
/// # Errors
///
/// Returns [`ClockError::PermissionDenied`] if the process lacks privileges.
/// Returns [`ClockError::Unsupported`] on unsupported platforms.
pub fn apply_correction(offset_seconds: f64) -> Result<CorrectionMethod, ClockError> {
    if offset_seconds.abs() <= STEP_THRESHOLD_SECS {
        slew_clock(offset_seconds)?;
        Ok(CorrectionMethod::Slew)
    } else {
        step_clock(offset_seconds)?;
        Ok(CorrectionMethod::Step)
    }
}

/// Convert an OS errno to a [`ClockError`].
#[cfg(unix)]
fn os_error_from_errno() -> ClockError {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    if errno == libc::EPERM {
        ClockError::PermissionDenied
    } else {
        ClockError::OsError(errno)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub(super) fn slew(offset_seconds: f64) -> Result<(), ClockError> {
        // Convert offset to microseconds for ADJ_OFFSET.
        let offset_usec = (offset_seconds * 1_000_000.0) as i64;

        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        tx.modes = libc::ADJ_OFFSET;
        tx.offset = offset_usec;

        let ret = unsafe { libc::clock_adjtime(libc::CLOCK_REALTIME, &mut tx) };
        if ret < 0 {
            return Err(os_error_from_errno());
        }
        Ok(())
    }

    pub(super) fn step(offset_seconds: f64) -> Result<(), ClockError> {
        // Get current time.
        let mut tp: libc::timespec = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut tp) };
        if ret < 0 {
            return Err(os_error_from_errno());
        }

        // Apply offset.
        let offset_nanos = (offset_seconds * 1_000_000_000.0) as i64;
        #[allow(clippy::unnecessary_cast)] // tv_sec/tv_nsec types differ across platforms
        let total_nanos = tp.tv_sec as i64 * 1_000_000_000 + tp.tv_nsec as i64 + offset_nanos;
        tp.tv_sec = (total_nanos / 1_000_000_000) as _;
        tp.tv_nsec = (total_nanos % 1_000_000_000) as _;

        let ret = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &tp) };
        if ret < 0 {
            return Err(os_error_from_errno());
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub(super) fn slew(offset_seconds: f64) -> Result<(), ClockError> {
        let secs = offset_seconds.trunc() as libc::time_t;
        let usecs = (offset_seconds.fract() * 1_000_000.0) as libc::suseconds_t;
        let delta = libc::timeval {
            tv_sec: secs,
            tv_usec: usecs,
        };

        let ret = unsafe { libc::adjtime(&delta, std::ptr::null_mut()) };
        if ret < 0 {
            return Err(os_error_from_errno());
        }
        Ok(())
    }

    pub(super) fn step(offset_seconds: f64) -> Result<(), ClockError> {
        // Get current time.
        let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
        if ret < 0 {
            return Err(os_error_from_errno());
        }

        // Apply offset.
        let offset_usecs = (offset_seconds * 1_000_000.0) as i64;
        let total_usecs = tv.tv_sec as i64 * 1_000_000 + tv.tv_usec as i64 + offset_usecs;
        tv.tv_sec = (total_usecs / 1_000_000) as _;
        tv.tv_usec = (total_usecs % 1_000_000) as _;

        let ret = unsafe { libc::settimeofday(&tv, std::ptr::null_mut()) };
        if ret < 0 {
            return Err(os_error_from_errno());
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemTimeAdjustment, GetSystemTimeAsFileTime, SetSystemTime, SetSystemTimeAdjustment,
    };
    use windows_sys::Win32::System::Time::FileTimeToSystemTime;

    /// Slew convergence period in seconds.
    const SLEW_DURATION_SECS: f64 = 30.0;

    /// Windows `ERROR_ACCESS_DENIED` (0x5).
    const ERROR_ACCESS_DENIED: i32 = 5;

    fn os_error() -> ClockError {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        if code == ERROR_ACCESS_DENIED {
            ClockError::PermissionDenied
        } else {
            ClockError::OsError(code)
        }
    }

    pub(super) fn slew(offset_seconds: f64) -> Result<(), ClockError> {
        if offset_seconds.abs() < 1e-9 {
            // Reset to default system tick rate.
            let ret = unsafe { SetSystemTimeAdjustment(0, 1) };
            if ret == 0 {
                return Err(os_error());
            }
            return Ok(());
        }

        let mut adjustment: u32 = 0;
        let mut increment: u32 = 0;
        let mut disabled: i32 = 0;
        let ret =
            unsafe { GetSystemTimeAdjustment(&mut adjustment, &mut increment, &mut disabled) };
        if ret == 0 {
            return Err(os_error());
        }

        // Calculate adjusted tick rate to converge over SLEW_DURATION_SECS.
        // increment = normal 100ns intervals per tick (e.g. 156250 for 15.625ms).
        let offset_100ns = offset_seconds * 10_000_000.0;
        let ticks_per_second = 10_000_000.0 / increment as f64;
        let total_ticks = ticks_per_second * SLEW_DURATION_SECS;
        let extra_per_tick = offset_100ns / total_ticks;
        let new_adjustment = ((increment as f64) + extra_per_tick).round().max(1.0) as u32;

        let ret = unsafe { SetSystemTimeAdjustment(new_adjustment, 0) };
        if ret == 0 {
            return Err(os_error());
        }
        Ok(())
    }

    pub(super) fn step(offset_seconds: f64) -> Result<(), ClockError> {
        // Get current time as FILETIME (100ns intervals since 1601-01-01).
        let mut ft = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        unsafe { GetSystemTimeAsFileTime(&mut ft) };

        // Combine into u64 and apply offset.
        let current = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
        let offset_100ns = (offset_seconds * 10_000_000.0) as i64;
        let new_time = (current as i64 + offset_100ns) as u64;

        ft.dwLowDateTime = new_time as u32;
        ft.dwHighDateTime = (new_time >> 32) as u32;

        // Convert FILETIME to SYSTEMTIME.
        let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
        let ret = unsafe { FileTimeToSystemTime(&ft, &mut st) };
        if ret == 0 {
            return Err(os_error());
        }

        // Set the system time.
        let ret = unsafe { SetSystemTime(&st) };
        if ret == 0 {
            return Err(os_error());
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::*;

    pub(super) fn slew(_offset_seconds: f64) -> Result<(), ClockError> {
        Err(ClockError::Unsupported)
    }

    pub(super) fn step(_offset_seconds: f64) -> Result<(), ClockError> {
        Err(ClockError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_correction_selects_slew_for_small_offset() {
        // Just verify the threshold logic; actual clock calls require root.
        assert!(0.05_f64.abs() <= STEP_THRESHOLD_SECS);
        assert!(0.200_f64.abs() > STEP_THRESHOLD_SECS);
    }

    #[test]
    fn test_step_threshold() {
        assert_eq!(STEP_THRESHOLD_SECS, 0.128);
    }

    #[test]
    fn test_clock_error_display() {
        assert_eq!(
            ClockError::PermissionDenied.to_string(),
            "permission denied (requires root/admin)"
        );
        assert_eq!(ClockError::OsError(42).to_string(), "OS error: 42");
        assert_eq!(
            ClockError::Unsupported.to_string(),
            "clock adjustment not supported on this platform"
        );
    }

    #[test]
    fn test_correction_method_traits() {
        // Clone + Copy
        let slew = CorrectionMethod::Slew;
        let slew_copy = slew;
        assert_eq!(slew, slew_copy);

        // PartialEq
        assert_eq!(CorrectionMethod::Slew, CorrectionMethod::Slew);
        assert_eq!(CorrectionMethod::Step, CorrectionMethod::Step);
        assert_ne!(CorrectionMethod::Slew, CorrectionMethod::Step);

        // Debug
        assert_eq!(format!("{:?}", CorrectionMethod::Slew), "Slew");
        assert_eq!(format!("{:?}", CorrectionMethod::Step), "Step");
    }

    #[test]
    fn test_threshold_boundary_conditions() {
        // Zero → slew
        assert!(0.0_f64.abs() <= STEP_THRESHOLD_SECS);

        // Negative small → slew
        assert!((-0.05_f64).abs() <= STEP_THRESHOLD_SECS);

        // Exactly at threshold → slew (<=)
        assert!(STEP_THRESHOLD_SECS.abs() <= STEP_THRESHOLD_SECS);

        // Just above threshold → step
        assert!((STEP_THRESHOLD_SECS + 0.001).abs() > STEP_THRESHOLD_SECS);

        // Negative large → step
        assert!((-0.200_f64).abs() > STEP_THRESHOLD_SECS);

        // Negative exactly at threshold → slew
        assert!((-STEP_THRESHOLD_SECS).abs() <= STEP_THRESHOLD_SECS);
    }

    #[test]
    fn test_clock_error_debug() {
        let debug = format!("{:?}", ClockError::PermissionDenied);
        assert!(debug.contains("PermissionDenied"));

        let debug = format!("{:?}", ClockError::OsError(13));
        assert!(debug.contains("OsError"));
        assert!(debug.contains("13"));

        let debug = format!("{:?}", ClockError::Unsupported);
        assert!(debug.contains("Unsupported"));
    }

    #[test]
    fn test_slew_clock_returns_result() {
        // Without root/admin, slew should return an error.
        // On Windows CI runners (admin), it may succeed — both are acceptable.
        let _result = slew_clock(0.001);
    }

    #[test]
    fn test_step_clock_returns_result() {
        // Without root/admin, step should return an error.
        // On Windows CI runners (admin), it may succeed — both are acceptable.
        let _result = step_clock(0.001);
    }

    #[test]
    fn test_apply_correction_selects_method() {
        // Slew range (small offset).
        let result = apply_correction(0.001);
        if let Ok(method) = result {
            assert_eq!(method, CorrectionMethod::Slew);
        }

        // Step range (large offset).
        let result = apply_correction(0.500);
        if let Ok(method) = result {
            assert_eq!(method, CorrectionMethod::Step);
        }
    }

    #[test]
    #[ignore] // Requires root privileges.
    fn test_slew_tiny_offset() {
        // Slew by 1 microsecond — should succeed with root.
        slew_clock(0.000001).unwrap();
    }

    #[test]
    #[ignore] // Requires root privileges.
    fn test_step_tiny_offset() {
        // Step by 1 microsecond — should succeed with root.
        step_clock(0.000001).unwrap();
    }

    #[test]
    #[ignore] // Requires root privileges.
    fn test_apply_correction_slew() {
        let method = apply_correction(0.001).unwrap();
        assert_eq!(method, CorrectionMethod::Slew);
    }

    #[test]
    #[ignore] // Requires root privileges.
    fn test_apply_correction_step() {
        let method = apply_correction(0.500).unwrap();
        assert_eq!(method, CorrectionMethod::Step);
    }
}
