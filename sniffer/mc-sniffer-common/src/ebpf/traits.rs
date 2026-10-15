pub trait EbpfAction {
    fn ok() -> Self;
    fn drop() -> Self;
    fn aborted() -> Self;
    fn default_action() -> Self;
}

pub trait EbpfContext {
    type Action: EbpfAction;

    /// Returns a bounds-checked pointer to a `T` at `i` bytes into the
    /// packet this context wraps.
    ///
    /// # Errors
    /// Returns `Self::Action`'s default/aborted action if `i + size_of::<T>()`
    /// would read past the end of the packet.
    fn index<T>(&self, i: usize) -> Result<*const T, Self::Action>;
    fn start(&self) -> usize;
    fn end(&self) -> usize;
    fn len(&self) -> usize {
        self.end() - self.start()
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait TryParse<C: EbpfContext>: Sized {
    type Error;

    /// Parses `Self` out of the packet `ctx` wraps.
    ///
    /// # Errors
    /// Returns `Self::Error` (`C::Action`) if the packet is too short for
    /// the header being parsed, or fails whatever semantic validation this
    /// type applies to it.
    fn try_parse(ctx: &C) -> Result<Self, Self::Error>;
}
