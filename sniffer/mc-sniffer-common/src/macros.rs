#[macro_export]
macro_rules! checked_slice {
    ($buf:ident[$range:expr], $error:expr) => {
        $buf.get($range).ok_or($error)?
    };
}

#[macro_export]
macro_rules! try_slice_into {
    ($buf:ident[$range:expr], $error:expr) => {
        checked_slice!($buf[$range], $error)
            .try_into()
            .map_err(|_| $error)?
    };
}

#[macro_export]
macro_rules! extract {
      ($ptr:expr) => {{
          let ptr = $ptr;
          unsafe { ptr.as_ref() }.ok_or_else($crate::ebpf::traits::EbpfAction::aborted)?
      }};
  }

#[cfg(test)]
mod scratch_verify {
    #[derive(Debug, PartialEq)]
    struct Malformed;

    fn try_it(packet: &[u8]) -> Result<u16, Malformed> {
        Ok(u16::from_be_bytes(try_slice_into!(packet[1..3], Malformed)))
    }

    #[test]
    fn it_works() {
        let buf = [0xAA, 0x00, 0x39, 0xBB];
        assert_eq!(try_it(&buf), Ok(0x0039));
    }

    #[test]
    fn it_errors_on_short_buf() {
        let buf = [0xAA];
        assert_eq!(try_it(&buf), Err(Malformed));
    }
}
