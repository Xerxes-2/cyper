use std::{
    borrow::Cow,
    fmt, io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::{
    io::{AsyncRead, AsyncWrite, util::Splittable},
    tls::{MaybeTlsStream, TlsStream},
};
use send_wrapper::SendWrapper;

trait CompatIo: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin {}

impl<T> CompatIo for T where T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin {}

struct CompatStream {
    io: Pin<Box<dyn CompatIo>>,
    is_write_vectored: bool,
}

enum HyperStreamInner<S: Splittable> {
    Compio(Box<MaybeTlsStream<S>>),
    Compat(CompatStream),
}

/// A stream wrapper for hyper.
pub struct HyperStream<S: Splittable>(SendWrapper<HyperStreamInner<S>>);

impl<S: Splittable> fmt::Debug for HyperStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HyperStream")
            .field("is_tls", &self.is_tls())
            .finish_non_exhaustive()
    }
}

impl<S: Splittable> HyperStream<S> {
    /// Create a new [`HyperStream`] from a plain stream.
    pub fn new_plain(s: S) -> Self {
        Self(SendWrapper::new(HyperStreamInner::Compio(Box::new(
            MaybeTlsStream::new_plain(s),
        ))))
    }

    /// Create a plain [`HyperStream`] using a futures-compatible transport.
    ///
    /// `is_write_vectored` must report whether the transport implements
    /// [`futures_util::AsyncWrite::poll_write_vectored`] efficiently.
    #[doc(hidden)]
    pub fn new_plain_compat<T>(s: T, is_write_vectored: bool) -> Self
    where
        T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + 'static,
    {
        Self(SendWrapper::new(HyperStreamInner::Compat(CompatStream {
            io: Box::pin(s),
            is_write_vectored,
        })))
    }

    /// Create a new [`HyperStream`] from a TLS stream.
    pub fn new_tls(s: TlsStream<S>) -> Self {
        Self(SendWrapper::new(HyperStreamInner::Compio(Box::new(
            MaybeTlsStream::new_tls(s),
        ))))
    }

    /// Whether the stream is TLS-encrypted.
    pub fn is_tls(&self) -> bool {
        match &*self.0 {
            HyperStreamInner::Compio(io) => io.is_tls(),
            HyperStreamInner::Compat(_) => false,
        }
    }

    /// Whether this stream uses futures-compatible IO internally.
    #[doc(hidden)]
    pub fn uses_compat_io(&self) -> bool {
        matches!(*self.0, HyperStreamInner::Compat(_))
    }
}

impl<S: Splittable + 'static> HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    /// Returns the negotiated ALPN protocol.
    pub fn negotiated_alpn(&self) -> Option<Cow<'_, [u8]>> {
        match &*self.0 {
            HyperStreamInner::Compio(io) => io.negotiated_alpn(),
            HyperStreamInner::Compat(_) => None,
        }
    }
}

impl<S: Splittable + 'static> hyper::rt::Read for HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let uninit = buf.initialize_unfilled();
        let capacity = uninit.len();
        let res = match &mut *self.0 {
            HyperStreamInner::Compio(io) => ready!(futures_util::AsyncRead::poll_read(
                Pin::new(&mut **io),
                cx,
                uninit,
            ))?,
            HyperStreamInner::Compat(stream) => ready!(stream.io.as_mut().poll_read(cx, uninit))?,
        };
        if res > capacity {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream reported more bytes than the read buffer can hold",
            )));
        }
        // SAFETY: `AsyncRead` receives only initialized bytes, and the byte count was
        // checked against the slice length above.
        unsafe { buf.advance(res) };
        Poll::Ready(Ok(()))
    }
}

impl<S: Splittable + 'static> futures_util::AsyncRead for HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self.0 {
            HyperStreamInner::Compio(io) => {
                futures_util::AsyncRead::poll_read(Pin::new(&mut **io), cx, buf)
            }
            HyperStreamInner::Compat(stream) => stream.io.as_mut().poll_read(cx, buf),
        }
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut *self.0 {
            HyperStreamInner::Compio(io) => {
                futures_util::AsyncRead::poll_read_vectored(Pin::new(&mut **io), cx, bufs)
            }
            HyperStreamInner::Compat(stream) => stream.io.as_mut().poll_read_vectored(cx, bufs),
        }
    }
}

impl<S: Splittable + 'static> hyper::rt::Write for HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncWrite::poll_write(Pin::new(&mut *self), cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncWrite::poll_write_vectored(Pin::new(&mut *self), cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        match &*self.0 {
            HyperStreamInner::Compio(_) => true,
            HyperStreamInner::Compat(stream) => stream.is_write_vectored,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::AsyncWrite::poll_flush(Pin::new(&mut *self), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::AsyncWrite::poll_close(Pin::new(&mut *self), cx)
    }
}

impl<S: Splittable + 'static> futures_util::AsyncWrite for HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self.0 {
            HyperStreamInner::Compio(io) => {
                futures_util::AsyncWrite::poll_write(Pin::new(&mut **io), cx, buf)
            }
            HyperStreamInner::Compat(stream) => stream.io.as_mut().poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut *self.0 {
            HyperStreamInner::Compio(io) => {
                futures_util::AsyncWrite::poll_write_vectored(Pin::new(&mut **io), cx, bufs)
            }
            HyperStreamInner::Compat(stream) => stream.io.as_mut().poll_write_vectored(cx, bufs),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self.0 {
            HyperStreamInner::Compio(io) => {
                futures_util::AsyncWrite::poll_flush(Pin::new(&mut **io), cx)
            }
            HyperStreamInner::Compat(stream) => stream.io.as_mut().poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self.0 {
            HyperStreamInner::Compio(io) => {
                futures_util::AsyncWrite::poll_close(Pin::new(&mut **io), cx)
            }
            HyperStreamInner::Compat(stream) => stream.io.as_mut().poll_close(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OverreportingIo;

    impl futures_util::AsyncRead for OverreportingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len() + 1))
        }
    }

    impl futures_util::AsyncWrite for OverreportingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn rejects_reads_larger_than_the_destination_buffer() {
        let mut stream =
            HyperStream::<compio::io::util::Null>::new_plain_compat(OverreportingIo, false);
        let mut bytes = [0; 8];
        let mut read_buf = hyper::rt::ReadBuf::new(&mut bytes);
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());

        let result =
            hyper::rt::Read::poll_read(Pin::new(&mut stream), &mut cx, read_buf.unfilled());

        assert!(matches!(
            result,
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
        ));
    }
}
