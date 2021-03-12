/// Helper macro to execute a system call that returns an `io::Result`.
//
// Macro must be defined before any modules that uses them.
#[allow(unused_macros)]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

cfg_os_poll! {
    mod selector;
    pub(crate) use self::selector::{event, Event, Events, Selector};

    mod sourcefd;
    pub use self::sourcefd::SourceFd;

    mod waker;
    pub(crate) use self::waker::Waker;

    cfg_net! {
        mod net;

        pub(crate) mod tcp;
        pub(crate) mod udp;
        pub(crate) mod uds;
        pub use self::uds::SocketAddr;
    }

    #[cfg(not(any(target_os = "illumos", target_os = "solaris")))]
    cfg_io_source! {
        use std::io;

        // Both `kqueue` and `epoll` don't need to hold any user space state.
        pub(crate) struct IoSourceState;

        impl IoSourceState {
            pub fn new() -> IoSourceState {
                IoSourceState
            }

            pub fn do_io<T, F, R>(&self, f: F, io: &T) -> io::Result<R>
            where
                F: FnOnce(&T) -> io::Result<R>,
            {
                // We don't hold state, so we can just call the function and
                // return.
                f(io)
            }
        }
    }

    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    cfg_io_source! {
        use std::io;
        use std::sync::Arc;
        use std::os::unix::io::AsRawFd;
        use std::os::unix::io::RawFd;

        use crate::{poll, Interest, Registry, Token};

        pub use self::selector::SelectorInner;

        struct InternalState {
            selector: Arc<SelectorInner>,
            token: Token,
            interests: Interest,
            socket: RawFd,
        }

        pub struct IoSourceState {
            inner: Option<Box<InternalState>>,
        }

        impl IoSourceState {
            pub fn new() -> IoSourceState {
                IoSourceState { inner: None }
            }

            pub fn do_io<T, F, R>(&self, f: F, io: &T) -> io::Result<R>
            where
                F: FnOnce(&T) -> io::Result<R>,
                T: AsRawFd,
            {
                let result = f(io);
                self.inner.as_ref().map_or(Ok(()), |state| {
                    state
                        .selector
                        .reregister(io.as_raw_fd(), state.token, state.interests)
                })?;
                result
            }

            pub fn register(
                &mut self,
                registry: &Registry,
                token: Token,
                interests: Interest,
                socket: RawFd,
            ) -> io::Result<()> {
                if self.inner.is_some() {
                    Err(io::ErrorKind::AlreadyExists.into())
                } else {
                    poll::selector(registry)
                        .register(socket, token, interests)
                        .map(|state| {
                            self.inner = Some(Box::new(state));
                        })
                }
            }

            pub fn reregister(
                &mut self,
                registry: &Registry,
                token: Token,
                interests: Interest,
            ) -> io::Result<()> {
                match self.inner.as_mut() {
                    Some(state) => {
                        poll::selector(registry)
                            .reregister(state.socket, token, interests)
                            .map(|()| {
                                state.token = token;
                                state.interests = interests;
                            })
                        }
                        None => Err(io::ErrorKind::NotFound.into()),
                }
            }

            pub fn deregister(&mut self) -> io::Result<()> {
                match self.inner.as_mut() {
                    Some(state) => {
                        self.inner = None;
                        Ok(())
                    }
                    None => Err(io::ErrorKind::NotFound.into()),
                }
            }
        }
    }

    cfg_os_ext! {
        pub(crate) mod pipe;
    }
}

cfg_not_os_poll! {
    cfg_net! {
        mod uds;
        pub use self::uds::SocketAddr;
    }

    cfg_any_os_ext! {
        mod sourcefd;
        pub use self::sourcefd::SourceFd;
    }
}
