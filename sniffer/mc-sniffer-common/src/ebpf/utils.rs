use aya_ebpf::bindings::xdp_action;
use aya_ebpf::programs::XdpContext;

pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

pub fn format_action(action: &xdp_action::Type) -> &str {
    match *action {
        xdp_action::XDP_ABORTED => "ABORTED",
        xdp_action::XDP_DROP => "DROP",
        xdp_action::XDP_PASS => "PASS",
        xdp_action::XDP_TX => "TX",
        xdp_action::XDP_REDIRECT => "REDIRECT",
        _ => "UNKNOWN",
    }
}
