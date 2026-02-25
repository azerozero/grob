use super::{TapEvent, TapSender};
use bytes::Bytes;
use futures::stream::Stream;
use pin_project::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Stream adapter that duplicates SSE chunks to the tap channel.
///
/// Same pattern as `DlpStream`: wraps an inner stream, forwarding all items
/// while also sending copies to the tap channel via `try_send` (non-blocking).
///
/// Zero impact on the hot path:
/// - `try_send` is non-blocking (drops if channel is full)
/// - `Bytes::clone()` is cheap (Arc-based reference count)
#[pin_project]
pub struct TapStream<S> {
    #[pin]
    inner: S,
    sender: Arc<TapSender>,
    request_id: String,
}

impl<S> TapStream<S>
where
    S: Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send,
{
    pub fn new(inner: S, sender: Arc<TapSender>, request_id: String) -> Self {
        Self {
            inner,
            sender,
            request_id,
        }
    }
}

impl<S> Stream for TapStream<S>
where
    S: Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send,
{
    type Item = Result<Bytes, crate::providers::error::ProviderError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Clone is cheap for Bytes (Arc-based)
                this.sender.try_send(TapEvent::StreamChunk {
                    request_id: this.request_id.clone(),
                    data: bytes.clone(),
                });
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                // Stream ended — notify tap worker
                this.sender.try_send(TapEvent::StreamEnd {
                    request_id: this.request_id.clone(),
                });
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::StreamExt;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_tap_stream_forwards_and_taps() {
        let (tx, mut rx) = mpsc::channel(16);
        let sender = Arc::new(TapSender { tx });

        // Create a simple stream of 3 chunks
        let chunks = vec![
            Ok(Bytes::from("chunk1")),
            Ok(Bytes::from("chunk2")),
            Ok(Bytes::from("chunk3")),
        ];
        let inner = futures::stream::iter(chunks);

        let mut tap_stream = TapStream::new(inner, sender, "test-req".to_string());

        // Consume the stream
        let mut collected = Vec::new();
        while let Some(item) = tap_stream.next().await {
            collected.push(item.unwrap());
        }

        // Verify all chunks were forwarded
        assert_eq!(collected.len(), 3);
        assert_eq!(&collected[0][..], b"chunk1");
        assert_eq!(&collected[1][..], b"chunk2");
        assert_eq!(&collected[2][..], b"chunk3");

        // Verify tap events: 3 StreamChunks + 1 StreamEnd
        let mut chunk_count = 0;
        let mut end_count = 0;
        while let Ok(event) = rx.try_recv() {
            match event {
                TapEvent::StreamChunk { request_id, .. } => {
                    assert_eq!(request_id, "test-req");
                    chunk_count += 1;
                }
                TapEvent::StreamEnd { request_id } => {
                    assert_eq!(request_id, "test-req");
                    end_count += 1;
                }
                _ => {}
            }
        }
        assert_eq!(chunk_count, 3);
        assert_eq!(end_count, 1);
    }
}
