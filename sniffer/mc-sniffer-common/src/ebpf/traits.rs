

pub trait EbpfAction {
    fn ok() -> Self;
    fn drop() -> Self;
    fn aborted() -> Self;
    fn default_action() -> Self;
}


pub trait EbpfContext {
    type Action: EbpfAction;

    fn index<T>(&self, i: usize) -> Result<*const T, Self::Action>;
    fn start(&self) -> usize;
    fn end(&self) -> usize;
}

pub trait ParseFrom<C: EbpfContext>: Sized {
    type Error;
    fn parse_from(ctx: &C) -> Result<Self, Self::Error>;
}