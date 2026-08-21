use aya_ebpf::bindings::xdp_action;
use crate::ebpf::traits::{EbpfAction, EbpfContext};

/// Returns a bounds-checked pointer to a `T` at `offset` bytes into the
/// packet `ctx` wraps.
///
/// # Errors
/// Returns [`xdp_action::XDP_ABORTED`] if `offset + size_of::<T>()` would
/// read past the end of the packet (`ctx.data_end()`) — i.e. there aren't
/// enough bytes remaining at `offset` to hold a `T`.
#[inline(always)]
pub fn ptr_at<T, C: EbpfContext>(ctx: &C, offset: usize) -> Result<*const T, C::Action> {
    let start = ctx.start();
    let end = ctx.end();
    let len = size_of::<T>();

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
