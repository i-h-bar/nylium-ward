use crate::ebpf::traits::{EbpfAction, EbpfContext};
use aya_ebpf::bindings::xdp_action;

/// Returns a bounds-checked pointer to a `T` at `offset` bytes into the
/// packet `ctx` wraps.
///
/// Generic over any [`EbpfContext`], so the actual bounds (`ctx.start()`/
/// `ctx.end()`) and the action returned on failure come from whichever
/// context type (`XdpContext`, ...) `C` is.
///
/// # Errors
/// Returns `C::Action`'s default/aborted action if `offset + size_of::<T>()`
/// would read past the end of the packet — i.e. there aren't enough bytes
/// remaining at `offset` to hold a `T`.
#[allow(clippy::inline_always)] // Needed for eBPF verifier
#[inline(always)]
pub fn ptr_at<T, C: EbpfContext>(ctx: &C, offset: usize) -> Result<*const T, C::Action> {
    let start = ctx.start();
    let end = ctx.end();
    // Hidden from LLVM on purpose. With a known `len` of 1 (any `u8`
    // read), LLVM rewrites `start + offset + 1 > end` as
    // `end > start + offset` -- equivalent, but the verifier only grants a
    // readable range from a comparison against a pointer with a non-zero
    // constant offset, so it rejects the load that follows. The verifier
    // still sees this as the constant it is (it tracks spilled constants),
    // so the `+ len` survives into the comparison and the range is granted.
    let len = unsafe { core::ptr::read_volatile(&size_of::<T>()) };

    if start + offset + len > end {
        return Err(C::Action::default_action());
    }

    Ok((start + offset) as *const T)
}

#[must_use]
pub const fn format_action(action: &xdp_action::Type) -> &str {
    match *action {
        xdp_action::XDP_ABORTED => "ABORTED",
        xdp_action::XDP_DROP => "DROP",
        xdp_action::XDP_PASS => "PASS",
        xdp_action::XDP_TX => "TX",
        xdp_action::XDP_REDIRECT => "REDIRECT",
        _ => "UNKNOWN",
    }
}
