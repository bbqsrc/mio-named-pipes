#![cfg(windows)]

extern crate kernel32;
extern crate lazycell;
#[macro_use]
extern crate log;
extern crate mio;
extern crate miow;

use std::ffi::OsStr;
use std::fmt;
use std::io::prelude::*;
use std::io;
use std::mem;
use std::os::windows::io::*;
use std::slice;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;

use lazycell::AtomicLazyCell;
use mio::{Registration, Poll, Token, PollOpt, Ready, Evented, SetReadiness};
use mio::windows;
use miow::iocp::CompletionStatus;
use miow::pipe;

mod from_raw_arc;
use from_raw_arc::FromRawArc;

macro_rules! offset_of {
    ($t:ty, $($field:ident).+) => (
        &(*(0 as *const $t)).$($field).+ as *const _ as usize
    )
}

macro_rules! overlapped2arc {
    ($e:expr, $t:ty, $($field:ident).+) => ({
        let offset = offset_of!($t, $($field).+);
        debug_assert!(offset < mem::size_of::<$t>());
        FromRawArc::from_raw(($e as usize - offset) as *mut $t)
    })
}

pub struct NamedPipe {
    ready_registration: AtomicLazyCell<Registration>,
    poll_registration: windows::Registration,
    inner: FromRawArc<Inner>,
}

struct Inner {
    handle: pipe::NamedPipe,
    readiness: AtomicLazyCell<SetReadiness>,

    connect: windows::Overlapped,
    connecting: AtomicBool,

    read: windows::Overlapped,
    write: windows::Overlapped,

    io: Mutex<Io>,
}

struct Io {
    read: State,
    write: State,
}

enum State {
    None,
    Pending(Vec<u8>, usize),
    Ok(Vec<u8>, usize),
    Err(io::Error),
}

impl NamedPipe {
    pub fn new<A: AsRef<OsStr>>(addr: A) -> io::Result<NamedPipe> {
        NamedPipe::_new(addr.as_ref())
    }

    fn _new(addr: &OsStr) -> io::Result<NamedPipe> {
        let pipe = try!(pipe::NamedPipe::new(addr));
        unsafe {
            Ok(NamedPipe::from_raw_handle(pipe.into_raw_handle()))
        }
    }

    pub fn connect(&self) -> io::Result<()> {
        // Make sure we're associated with an IOCP object
        if self.ready_registration.borrow().is_none() {
            return Err(mio::would_block())
        }

        // "Acquire the connecting lock" or otherwise just make sure we're the
        // only operation that's using the `connect` overlapped instance.
        if self.inner.connecting.swap(true, SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Other, "already connecting"))
        }

        // Now that we've flagged ourselves in the connecting state, issue the
        // connection attempt. Afterwards interpret the return value and set
        // internal state accordingly.
        let res = unsafe {
            let overlapped = &mut *self.inner.connect.as_mut_ptr();
            self.inner.handle.connect_overlapped(overlapped)
        };

        match res {
            // If the overlapped operation was successful then we forget a copy
            // of the arc we hold internally. This ensures that when the
            // completion status comes in for the I/O operation finishing it'll
            // have a reference associated with it and our data will still be
            // valid. The `connect_done` function will "reify" this forgotten
            // pointer to drop the refcount on the other side.
            //
            // TODO: are we sure an IOCP notification comes in regardless of
            // `e`?
            Ok(e) => {
                trace!("connect ok: {}", e);
                mem::forget(self.inner.clone());
                Ok(())
            }

            // TODO: are we sure no IOCP notification comes in here?
            Err(e) => {
                trace!("connect error: {}", e);
                self.inner.connecting.store(false, SeqCst);
                Err(e)
            }
        }
    }

    pub fn disconnect(&self) -> io::Result<()> {
        self.inner.handle.disconnect()
    }
}

impl Read for NamedPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        <&NamedPipe as Read>::read(&mut &*self, buf)
    }
}

impl Write for NamedPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        <&NamedPipe as Write>::write(&mut &*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        <&NamedPipe as Write>::flush(&mut &*self)
    }
}

impl<'a> Read for &'a NamedPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Make sure we're registered
        if self.ready_registration.borrow().is_none() {
            return Err(mio::would_block())
        }

        let mut state = self.inner.io.lock().unwrap();
        match mem::replace(&mut state.read, State::None) {
            // In theory not possible with `ready_registration` checked above,
            // but return would block for now.
            State::None => Err(mio::would_block()),

            // A read is in flight, still waiting for it to finish
            State::Pending(buf, amt) => {
                state.read = State::Pending(buf, amt);
                Err(mio::would_block())
            }

            // We previously read something into `data`, try to copy out some
            // data. If we copy out all the data schedule a new read and
            // otherwise store the buffer to get read later.
            State::Ok(data, cur) => {
                let n = {
                    let mut remaining = &data[cur..];
                    try!(remaining.read(buf))
                };
                let next = cur + n;
                if next != data.len() {
                    state.read = State::Ok(data, next);
                } else {
                    Inner::schedule_read(&self.inner, &mut state);
                }
                Ok(n)
            }

            // Looks like an in-flight read hit an error, return that here while
            // we schedule a new one.
            State::Err(e) => {
                Inner::schedule_read(&self.inner, &mut state);
                Err(e)
            }
        }
    }
}

impl<'a> Write for &'a NamedPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Make sure we're registered
        if self.ready_registration.borrow().is_none() {
            return Err(mio::would_block())
        }

        // Make sure there's no writes pending
        let mut io = self.inner.io.lock().unwrap();
        match io.write {
            State::None => {}
            _ => return Err(mio::would_block())
        }

        // Move `buf` onto the heap and fire off the write
        //
        // TODO: need to be smarter about buffer management here
        Inner::schedule_write(&self.inner, buf.to_vec(), 0, &mut io);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO: `FlushFileBuffers` somehow?
        Ok(())
    }
}

impl Evented for NamedPipe {
    fn register(&self,
                poll: &Poll,
                token: Token,
                interest: Ready,
                opts: PollOpt) -> io::Result<()> {
        // First, register the handle with the event loop
        unsafe {
            try!(self.poll_registration.register_handle(&self.inner.handle,
                                                        token,
                                                        poll));
        }

        // Next, create our `SetReadiness` pair we're going to work with. Here
        // if we fail in `ready_registration` then we assume that registration
        // already succeeded (or is in the process of succeeding) elsewhere so
        // we bail out.
        let (r, s) = Registration::new(poll, token, interest, opts);
        match self.ready_registration.fill(r) {
            Ok(()) => {}
            Err(_) => return Ok(()),
        }
        assert!(self.inner.readiness.fill(s).is_ok());
        Inner::schedule_read(&self.inner, &mut self.inner.io.lock().unwrap());
        Ok(())
    }

    fn reregister(&self,
                  poll: &Poll,
                  token: Token,
                  interest: Ready,
                  opts: PollOpt) -> io::Result<()> {
        // Validate `Poll` and that we were previously registered
        unsafe {
            try!(self.poll_registration.reregister_handle(&self.inner.handle,
                                                          token,
                                                          poll));
        }

        // At this point we should for sure have `ready_registration` unless
        // we're racing with `register` above, so just return a bland error if
        // the borrow fails.
        match self.ready_registration.borrow() {
            Some(r) => r.update(poll, token, interest, opts),
            None => Err(io::Error::new(io::ErrorKind::Other, "not registered")),
        }
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        // Validate `Poll` and deregister ourselves
        unsafe {
            try!(self.poll_registration.deregister_handle(&self.inner.handle, poll));
        }

        // Deregister the registration, which this should always succeed.
        match self.ready_registration.borrow() {
            Some(r) => r.deregister(poll),
            None => Err(io::Error::new(io::ErrorKind::Other, "not registered")),
        }
    }
}

impl AsRawHandle for NamedPipe {
    fn as_raw_handle(&self) -> RawHandle {
        self.inner.handle.as_raw_handle()
    }
}

impl FromRawHandle for NamedPipe {
    unsafe fn from_raw_handle(handle: RawHandle) -> NamedPipe {
        NamedPipe {
            ready_registration: AtomicLazyCell::new(),
            poll_registration: windows::Registration::new(),
            inner: FromRawArc::new(Inner {
                handle: pipe::NamedPipe::from_raw_handle(handle),
                readiness: AtomicLazyCell::new(),
                connect: windows::Overlapped::new(connect_done),
                connecting: AtomicBool::new(false),
                read: windows::Overlapped::new(read_done),
                write: windows::Overlapped::new(write_done),
                io: Mutex::new(Io {
                    read: State::None,
                    write: State::None,
                }),
            }),
        }
    }
}

impl fmt::Debug for NamedPipe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.handle.fmt(f)
    }
}

impl Drop for NamedPipe {
    fn drop(&mut self) {
        // Cancel pending reads/connects, but don't cancel writes to ensure that
        // everything is flushed out.
        unsafe {
            if self.inner.connecting.load(SeqCst) {
                drop(cancel(&self.inner.handle, &self.inner.connect));
            }
            let io = self.inner.io.lock().unwrap();
            match io.read {
                State::Pending(..) => {
                    drop(cancel(&self.inner.handle, &self.inner.read));
                }
                _ => {}
            }
        }
    }
}

impl Inner {
    fn schedule_read(me: &FromRawArc<Inner>, io: &mut Io) {
        // Check to see if a read is already scheduled/completed
        match io.read {
            State::None => {}
            _ => return,
        }

        // Turn off our read readiness
        let readiness = me.readiness.borrow().unwrap();
        let ready = readiness.readiness();
        readiness.set_readiness(ready & !Ready::readable())
                 .expect("event loop seems gone");

        // Allocate a buffer and schedule the read.
        //
        // TODO: need to be smarter about buffer management here
        let mut buf = Vec::with_capacity(8 * 1024);
        let e = unsafe {
            let overlapped = &mut *me.read.as_mut_ptr();
            let slice = slice::from_raw_parts_mut(buf.as_mut_ptr(),
                                                  buf.capacity());
            me.handle.read_overlapped(slice, overlapped)
        };

        match e {
            // See `connect` above for the rationale behind `forget`
            Ok(e) => {
                trace!("schedule read success: {}", e);
                io.read = State::Pending(buf, 0); // 0 is ignored on read side
                mem::forget(me.clone())
            }
            Err(e) => {
                trace!("schedule read error: {}", e);
                io.read = State::Err(e);
                readiness.set_readiness(ready | Ready::readable())
                         .expect("event loop still seems gone");
            }
        }
    }

    fn schedule_write(me: &FromRawArc<Inner>,
                      buf: Vec<u8>,
                      pos: usize,
                      io: &mut Io) {
        // Very similar to `schedule_read` above, just done for the write half.
        let readiness = me.readiness.borrow().unwrap();
        let ready = readiness.readiness();
        readiness.set_readiness(ready & !Ready::writable())
                 .expect("event loop seems gone");

        let e = unsafe {
            let overlapped = &mut *me.write.as_mut_ptr();
            me.handle.write_overlapped(&buf[pos..], overlapped)
        };

        match e {
            // See `connect` above for the rationale behind `forget`
            Ok(e) => {
                trace!("schedule write success: {}", e);
                io.write = State::Pending(buf, pos);
                mem::forget(me.clone())
            }
            Err(e) => {
                trace!("schedule write error: {}", e);
                io.write = State::Err(e);
                readiness.set_readiness(ready | Ready::writable())
                         .expect("event loop still seems gone");
            }
        }
    }
}

unsafe fn cancel(handle: &AsRawHandle,
                 overlapped: &windows::Overlapped) -> io::Result<()> {
    let overlapped = (*overlapped.as_mut_ptr()).raw();
    let ret = kernel32::CancelIoEx(handle.as_raw_handle(), overlapped);
    if ret == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn connect_done(status: &CompletionStatus) {
    trace!("connect done");

    // Acquire the `FromRawArc<Inner>`. Note that we should be guaranteed that
    // the refcount is available to us due to the `mem::forget` in
    // `connect` above.
    let me = unsafe {
        overlapped2arc!(status.overlapped(), Inner, connect)
    };

    // Now that we're connected we should be writable
    let readiness = me.readiness.borrow().unwrap();
    let ready = readiness.readiness();
    readiness.set_readiness(ready | Ready::writable())
             .expect("event loop seems gone");

    // Also kick off a read
    let mut io = me.io.lock().unwrap();
    Inner::schedule_read(&me, &mut io);
}

fn read_done(status: &CompletionStatus) {
    trace!("read finished, bytes={}", status.bytes_transferred());

    // Acquire the `FromRawArc<Inner>`. Note that we should be guaranteed that
    // the refcount is available to us due to the `mem::forget` in
    // `schedule_read` above.
    let me = unsafe {
        overlapped2arc!(status.overlapped(), Inner, read)
    };

    // Move from the `Pending` to `Ok` state.
    let mut io = me.io.lock().unwrap();
    let mut buf = match mem::replace(&mut io.read, State::None) {
        State::Pending(buf, _) => buf,
        _ => unreachable!(),
    };
    unsafe {
        buf.set_len(status.bytes_transferred() as usize);
    }
    io.read = State::Ok(buf, 0);

    // Flag our readiness that we've got data.
    let readiness = me.readiness.borrow().unwrap();
    let ready = readiness.readiness();
    readiness.set_readiness(ready | Ready::readable())
             .expect("event loop seems gone");
}

fn write_done(status: &CompletionStatus) {
    trace!("write finished, bytes={}", status.bytes_transferred());
    // Acquire the `FromRawArc<Inner>`. Note that we should be guaranteed that
    // the refcount is available to us due to the `mem::forget` in
    // `schedule_write` above.
    let me = unsafe {
        overlapped2arc!(status.overlapped(), Inner, write)
    };

    // Make the state change out of `Pending`. If we wrote the entire buffer
    // then we're writable again and otherwise we schedule another write.
    let mut io = me.io.lock().unwrap();
    let (buf, pos) = match mem::replace(&mut io.write, State::None) {
        State::Pending(buf, pos) => (buf, pos),
        _ => unreachable!(),
    };
    let new_pos = pos + (status.bytes_transferred() as usize);
    if new_pos == buf.len() {
        let readiness = me.readiness.borrow().unwrap();
        let ready = readiness.readiness();
        readiness.set_readiness(ready | Ready::writable())
                 .expect("event loop seems gone");
    } else {
        Inner::schedule_write(&me, buf, new_pos, &mut io);
    }
}
