#[cfg(any(target_os = "android", target_os = "linux"))]
mod epoll;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) use self::epoll::{event, Event, Events, Selector};

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
mod kqueue;

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub(crate) use self::kqueue::{event, Event, Events, Selector};

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
mod evport;

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
pub(crate) use self::evport::{event, Event, Events, Selector, SelectorInner};
