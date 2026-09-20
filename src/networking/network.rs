use std::{io, marker::PhantomData, num::NonZero};

use serde::{Deserialize, Serialize};

/// Represents a directive to receive objects from a specified participant in the network.
#[derive(Debug)]
pub struct ReceiveRequest<T>
where
    T: for<'de> Deserialize<'de>,
{
    /// The integer identifier of the source node.
    pub from: usize,
    /// The expected number of elements to receive, or `None` if zero.
    pub count: Option<NonZero<usize>>,
    phantom: PhantomData<T>,
}

impl<T> ReceiveRequest<T>
where
    T: for<'de> Deserialize<'de>,
{
    /// Constructs a new `ReceiveRequest` for a deterministic number of elements.
    pub fn new(from: usize, count: usize) -> Self {
        Self {
            from,
            count: NonZero::new(count),
            phantom: PhantomData,
        }
    }
}

use std::borrow::Cow;

/// Represents a directive to transmit an object to a specified participant in the network.
#[derive(Debug)]
pub struct SendRequest<'a, T>
where
    T: Serialize + Clone,
{
    /// The integer identifier of the destination node.
    pub to: usize,
    /// The payload object, which may be owned or borrowed.
    pub data: Cow<'a, T>,
}

impl<'a, T> SendRequest<'a, T>
where
    T: Serialize + Clone,
{
    /// Constructs a new `SendRequest` taking ownership of the provided data payload.
    pub fn new(to: usize, data: T) -> Self {
        Self {
            to,
            data: Cow::Owned(data),
        }
    }

    /// Constructs a new `SendRequest` borrowing the provided data payload.
    pub fn from_ref(to: usize, data: &'a T) -> Self {
        Self {
            to,
            data: Cow::Borrowed(data),
        }
    }
}

/// Represents the length of transmitted bytes over the network interface.
pub type SendLen = usize;
/// Represents the length of received bytes over the network interface.
pub type RecvLen = usize;

/// Asynchronous communication interface for a distributed, multi-node system.
///
/// This trait defines the core operations for cluster topology resolution, raw byte
/// transport, and strongly-typed object serialization via `postcard`. It relies on
/// integer-based node addressing, enforcing the invariant `my_id() < n_players()`.
/// Provided methods abstract the underlying I/O routines into typed, asynchronous
/// batch processing operations to minimize network fragmentation.
pub trait Network {
    /// Retrieves the total number of participants in the network.
    fn n_players(&self) -> usize;

    /// Retrieves the local node identifier within the network.
    /// Invariant: `my_id() < n_players()`.
    fn my_id(&self) -> usize;

    /// Transmits a raw byte slice to the designated `to` node asynchronously. Returns the number of
    /// bytes sent.
    fn send(&mut self, to: usize, data: &[u8]) -> impl Future<Output = io::Result<SendLen>>;

    /// Transmits a raw byte slice to all network participants asynchronously. Returns the number of
    /// bytes sent.
    fn broadcast(&mut self, data: &[u8]) -> impl Future<Output = io::Result<SendLen>>;

    /// Awaits and retrieves raw byte data from the designated `from` node asynchronously. Returns
    /// the data vector and byte count.
    fn recv(&mut self, from: usize) -> impl Future<Output = io::Result<(Vec<u8>, RecvLen)>>;

    /// Serializes a single object using `postcard` and transmits the resulting byte vector to the
    /// designated `to` node.
    fn send_object<T>(&mut self, to: usize, obj: &T) -> impl Future<Output = io::Result<SendLen>>
    where
        T: Serialize,
    {
        async move { self.send_objects(to, core::slice::from_ref(obj)).await }
    }

    /// Serializes a slice of objects using `postcard` and transmits the resulting byte vector to
    /// the designated `to` node.
    fn send_objects<T>(
        &mut self,
        to: usize,
        objs: &[T],
    ) -> impl Future<Output = io::Result<SendLen>>
    where
        T: Serialize,
    {
        async move {
            let bytes = postcard::to_stdvec(objs).map_err(io::Error::other)?;
            self.send(to, &bytes).await
        }
    }

    /// Serializes a single object using `postcard` and broadcasts the resulting byte vector to all
    /// network participants.
    fn broadcast_object<T>(&mut self, obj: &T) -> impl Future<Output = io::Result<SendLen>>
    where
        T: Serialize,
    {
        async move { self.broadcast_objects(core::slice::from_ref(obj)).await }
    }

    /// Serializes a slice of objects using `postcard` and broadcasts the resulting byte vector to
    /// all network participants.
    fn broadcast_objects<T>(&mut self, objs: &[T]) -> impl Future<Output = io::Result<SendLen>>
    where
        T: Serialize,
    {
        async move {
            let data = postcard::to_stdvec(objs).map_err(io::Error::other)?;
            self.broadcast(&data).await
        }
    }

    /// Awaits byte data from the `from` node, deserializing it via `postcard` into a single object
    /// of type `T`.
    fn recv_object<T>(&mut self, from: usize) -> impl Future<Output = io::Result<(T, RecvLen)>>
    where
        T: for<'de> Deserialize<'de>,
    {
        async move {
            let (vec, recv_len) = self.recv_objects(from, Some(1)).await?;
            Ok((vec.into_iter().next().unwrap(), recv_len))
        }
    }

    /// Awaits byte data from the `from` node, deserializing it via `postcard` into a vector of type
    /// `T`. Validates the resulting vector length against `count` if `Some` is provided.
    fn recv_objects<T>(
        &mut self,
        from: usize,
        count: Option<usize>,
    ) -> impl Future<Output = io::Result<(Vec<T>, RecvLen)>>
    where
        T: for<'de> Deserialize<'de>,
    {
        async move {
            let (bytes, recv_len) = self.recv(from).await?;
            let objs: Vec<T> = postcard::from_bytes(&bytes)
                .map_err(|e| io::Error::other(format!("Deserialization error, {}", e)))?;
            if let Some(count) = count
                && objs.len() != count
            {
                return Err(io::Error::other(format!(
                    "Batch size mismatch. Expected {}, got {}",
                    count,
                    objs.len()
                )));
            }
            Ok((objs, recv_len))
        }
    }

    /// Processes an iterator of `ReceiveRequest` parameters to await and deserialize multiple
    /// batches of objects from specified sources.
    fn recv_objects_many<'a, T, I>(
        &mut self,
        request: I,
    ) -> impl Future<Output = io::Result<(Vec<Vec<T>>, RecvLen)>>
    where
        T: for<'de> Deserialize<'de> + 'a,
        I: IntoIterator<Item = &'a ReceiveRequest<T>>;

    /// Processes an iterator of `SendRequest` parameters to serialize and transmit multiple
    /// payloads to specified targets.
    fn send_objects_many<'a, T, I>(
        &mut self,
        request: I,
    ) -> impl Future<Output = io::Result<SendLen>>
    where
        T: Serialize + Clone + 'a,
        I: IntoIterator<Item = &'a SendRequest<'a, T>>;
}
