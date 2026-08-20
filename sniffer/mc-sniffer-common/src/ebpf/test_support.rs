//! Test-only helper for building a *real*, unmodified `XdpContext` in a
//! host unit test — not a mock, not a reimplementation of the parsing logic
//! against a `&[u8]`. The functions under test (`check_header`,
//! `Ipv4Packet::try_from`, ...) call `ctx.data()`/`ctx.data_end()`, which
//! read straight off an `xdp_md` struct's `data`/`data_end` fields and
//! reinterpret them as a pointer (see `aya_ebpf::programs::XdpContext`).
//!
//! The catch: those fields are `u32`, not `usize`. On a real 64-bit host, a
//! normal stack/heap allocation's address is nearly always far above
//! `u32::MAX` (verified directly — a plain stack buffer here sits around
//! `0x7ffe...`), so naively pointing `xdp_md.data` at one would silently
//! truncate the address into garbage. `mmap` with `MAP_32BIT` (Linux,
//! x86-64) forces the allocation into the low 2GiB of address space
//! instead, so the real pointer genuinely fits — confirmed empirically
//! before writing this (a throwaway mmap call, checked the returned address
//! against `u32::MAX`, wrote and read back a byte through it).
//!
//! This means the tests using [`FakePacket`] exercise the *exact* compiled
//! code that ships in the eBPF program — `ptr_at`, `ether_type()`, the real
//! `unsafe` dereferences — not a stand-in for it.

use aya_ebpf::bindings::xdp_md;
use aya_ebpf::programs::XdpContext;

pub struct FakePacket {
    ptr: *mut u8,
    len: usize,
    md: xdp_md,
}

impl FakePacket {
    /// Copies `bytes` into a fresh, low-address mmap'd region sized
    /// *exactly* to `bytes.len()` — not page-rounded from the code under
    /// test's point of view — so `data_end` genuinely reflects "no more
    /// bytes after this," and boundary/too-short tests behave like they
    /// would against a real, tightly-sized packet buffer.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        let len = bytes.len();
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len.max(1),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
                -1,
                0,
            )
        };
        assert_ne!(
            raw,
            libc::MAP_FAILED,
            "mmap(MAP_32BIT) failed: {}",
            std::io::Error::last_os_error()
        );
        let ptr = raw.cast::<u8>();
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
        }

        let start = u32::try_from(ptr as usize).expect("mmap(MAP_32BIT) address must fit in u32");
        let end = start + u32::try_from(len).expect("test fixture too large");

        Self {
            ptr,
            len,
            md: xdp_md {
                data: start,
                data_end: end,
                data_meta: 0,
                ingress_ifindex: 0,
                rx_queue_index: 0,
                egress_ifindex: 0,
            },
        }
    }

    pub fn ctx(&mut self) -> XdpContext {
        XdpContext::new(&raw mut self.md)
    }
}

impl Drop for FakePacket {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.cast(), self.len.max(1));
        }
    }
}