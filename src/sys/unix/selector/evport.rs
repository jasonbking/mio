use crate::{Interest, Token};
use log::error;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use std::{cmp, io, ptr};

use libc::PORT_SOURCE_FD;
use libc::{self, c_uint};
use libc::{POLLIN, POLLOUT};

#[cfg(debug_assertions)]
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug)]
pub struct Selector {
    #[cfg(debug_assertions)]
    id: usize,
    inner: Arc<SelectorInner>,
    #[cfg(debug_assertions)]
    has_waker: AtomicBool,
}

impl Selector {
    pub fn new() -> io::Result<Selector> {
        Selector {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            inner: Arc::new(SelectorInner::new()?),
            has_waker: AtomicBool::new(false),
        }
    }

    pub fn try_clone(&self) -> io::Result<Selector> {
        Selector {
            // It's the same selector, so we use the same id.
            #[cfg(debug_assertions)]
            id: self.id,
            inner: Arc::clone(&self.inner),
            has_waker: AtomicBool::new(self.has_waker.load(Ordering::Acquire),
        }
    }

    pub fn select(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.select(events, timeout)
    }

    pub fn register(&self, fd: RawFd, token: Token, interests: Interest) -> io::Result<InternalState> {
        self.inner.register(&self.inner, fd, token, interests)
    }

    pub fn reregister(&self, fd: RawFd, token: Token, interests: Interest) -> io::Result<()> {
        self.inner.register(&self.inner, fd, token, interests)
    }

    pub fn deregister(&self, fd: RawFd) -> io::Result<()> {
        self.inner.deregister(fd)
    }

    #[cfg(debug_assertions)]
    pub fn register_waker(&self) -> bool {
        self.has_waker.swap(true, Ordering::AcqRel)
    }

    pub fn wake(&self, token: Token) -> io::Result<()> {
        self.inner.wake(token)
    }
}

struct SelectorInner {
    port: RawFd,
}

impl SelectorInner {
    pub fn new() -> io::Result<Self> {
        syscall!(port_create())
            .and_then(|p| syscall!(fcntl(p, libc::F_SETFD, libc::FD_CLOEXEC)).map(|_| p))
            .map(|p| SelectorInner {
                port: p,
            })
    }

    pub fn select(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        let timeout = timeout.map(|to| libc::timespec {
            tv_sec: cmp::min(to.as_secs(), libc::time_t::max_value() as u64) as libc::time_t,
            // `Duration::subsec_nanos` is guaranteed to be less than one
            // billion (the number of nanoseconds in a second), making the
            // cast to i32 safe. The cast itself is needed for platforms
            // where C's long is only 32 bits.
            tv_nsec: libc::c_long::from(to.subsec_nanos() as i32),
        });
        let timeout = timeout
            .as_ref()
            .map(|s| s as *const _)
            .unwrap_or(ptr::null_mut());

        events.clear();

        let mut nget: u32 = 1;
        syscall!(port_getn(
            self.port,
            events.as_mut_ptr(),
            events.capacity() as c_uint,
            &mut nget as *mut c_uint,
            timeout as *mut ::libc::timespec,
        ))?;

        // If port_getn() succeeds, nget will contain the number of
        // entries, so this is safe.
        unsafe { events.set_len(nget as usize) };

        Ok(())
    }

    pub fn register(this: &Arc<Self>, fd: RawFd, token: Token, interests: Interest) -> io::Result<InternalState> {
        let mut flags = 0;

        if interests.is_readable() {
            flags |= POLLIN;
        }

        if interests.is_writable() {
            flags |= POLLOUT;
        }

        syscall!(port_associate(
            self.port,
            PORT_SOURCE_FD,
            fd as usize,
            flags as i32,
            token.0 as *mut libc::c_void,
        ))
        .map(|_| InternalState {
            selector: this.clone(),
            token: token,
            interests: interests,
            socket: fd
        })
    }

    pub fn deregister(&self, fd: RawFd) -> io::Result<()> {
        syscall!(port_dissociate(
            self.port,
            libc::PORT_SOURCE_FD,
            fd as libc::uintptr_t
        ))
        .map(|_| ())
    }

    pub fn wake(&self, token: Token) -> io::Result<()> {
        syscall!(port_send(self.port, 0, token.0 as *mut libc::c_void)).map(|_| ())
    }
}

cfg_io_source! {
    #[cfg(debug_assertions)]
    impl Selector {
        pub fn id(&self) -> usize {
            self.id
        }
    }
}

impl AsRawFd for Selector {
    fn as_raw_fd(&self) -> RawFd {
        self.port
    }
}

impl Drop for Selector {
    fn drop(&mut self) {
        if let Err(err) = syscall!(close(self.port)) {
            error!("error closing event port: {}", err);
        }
    }
}

pub type Event = libc::port_event;
pub struct Events(Vec<libc::port_event>);

impl Events {
    pub fn with_capacity(capacity: usize) -> Events {
        Events(Vec::with_capacity(capacity))
    }
}

impl Deref for Events {
    type Target = Vec<libc::port_event>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Events {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

unsafe impl Send for Events {}
unsafe impl Sync for Events {}

pub mod event {
    use std::fmt;

    use crate::sys::Event;
    use crate::Token;

    use libc::{c_int, c_short};

    pub fn token(event: &Event) -> Token {
        Token(event.portev_user as usize)
    }

    pub fn is_readable(event: &Event) -> bool {
        (event.portev_events & libc::POLLIN as c_int) != 0
            && event.portev_source as c_int == libc::PORT_SOURCE_FD
    }

    pub fn is_writable(event: &Event) -> bool {
        (event.portev_events & libc::POLLOUT as c_int) != 0
            && event.portev_source as c_int == libc::PORT_SOURCE_FD
    }

    pub fn is_error(event: &Event) -> bool {
        (event.portev_events & libc::POLLERR as c_int) != 0
            && event.portev_source as c_int == libc::PORT_SOURCE_FD
    }

    pub fn is_read_closed(event: &Event) -> bool {
        (event.portev_events & libc::POLLHUP as c_int) != 0
            && event.portev_source as c_int == libc::PORT_SOURCE_FD
    }

    pub fn is_write_closed(event: &Event) -> bool {
        (event.portev_events & libc::POLLHUP as c_int) != 0
            && event.portev_source as c_int == libc::PORT_SOURCE_FD
    }

    pub fn is_priority(_: &Event) -> bool {
        false
    }

    pub fn is_aio(event: &Event) -> bool {
        event.portev_source as c_int == libc::PORT_SOURCE_AIO
    }

    pub fn is_lio(_: &Event) -> bool {
        false
    }

    pub fn debug_details(f: &mut fmt::Formatter<'_>, event: &Event) -> fmt::Result {
        debug_detail!(
            SourceDetails(libc::c_int),
            PartialEq::eq,
            libc::PORT_SOURCE_AIO,
            libc::PORT_SOURCE_TIMER,
            libc::PORT_SOURCE_USER,
            libc::PORT_SOURCE_FD,
            libc::PORT_SOURCE_ALERT,
            libc::PORT_SOURCE_MQ,
            libc::PORT_SOURCE_FILE,
        );

        #[allow(clippy::trivially_copy_pass_by_ref)]
        fn check_flag(got: &c_int, want: &c_short) -> bool {
            (got & *want as c_int) != 0
        }

        debug_detail!(EventDetails(c_int), check_flag, libc::POLLIN, libc::POLLOUT,);

        let object = event.portev_object;
        let user = event.portev_user;

        f.debug_struct("port_event")
            .field(
                "portev_events",
                &EventDetails(event.portev_events as libc::c_int),
            )
            .field(
                "portev_source",
                &SourceDetails(event.portev_source as libc::c_int),
            )
            .field("portev_object", &object)
            .field("portev_user", &user)
            .finish()
    }
}
