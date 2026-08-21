use aya_ebpf::bindings::xdp_action;
use aya_ebpf::programs::XdpContext;
use crate::ebpf::traits::{EbpfAction, EbpfContext};
use crate::ebpf::utils::ptr_at;

impl EbpfAction for xdp_action::Type {
    fn ok() -> Self { xdp_action::XDP_PASS }
    fn drop() -> Self { xdp_action::XDP_DROP }
    fn aborted() -> Self { xdp_action::XDP_ABORTED }

    fn default_action() -> Self {
        Self::aborted()
    }
}

impl EbpfContext for XdpContext {
    type Action = xdp_action::Type;

    #[inline(always)]
    fn index<T>(&self, i: usize) -> Result<*const T, Self::Action> {
        ptr_at(self, i)
    }

    #[inline(always)]
    fn start(&self) -> usize {
        self.data()
    }

    #[inline(always)]
    fn end(&self) -> usize {
        self.data_end()
    }
}