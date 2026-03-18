use ed25519_dalek::SigningKey;
use futures::{TryFutureExt as _, future};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

use super::identity::NodeIdentities;
use super::secure_stream::{ConnectionRole, SecureStream};
use crate::networking::{Network, OwnedOrRef, ReceiveRequest, RecvLen, SendLen, SendRequest};

pub struct MeshNetwork {
    my_id: usize,
    n_parties: usize,
    channels: Vec<Option<SecureStream<TcpStream>>>,
}

impl Network for MeshNetwork {
    fn my_id(&self) -> usize {
        self.my_id
    }

    fn n_players(&self) -> usize {
        self.n_parties
    }

    fn send(&mut self, to: usize, data: &[u8]) -> impl Future<Output = io::Result<SendLen>> {
        let channel = self.get_channel_mut(to);
        async move {
            let channel = channel?;
            channel
                .send(data)
                .map_err(|e| {
                    io::Error::other(format!(
                        "Failed to send {} bytes to {}: {}",
                        data.len(),
                        to,
                        e
                    ))
                })
                .await
        }
    }

    async fn broadcast(&mut self, data: &[u8]) -> io::Result<SendLen> {
        let mut total_bytes_sent = 0;
        for to in 0..self.n_parties {
            if to == self.my_id {
                continue;
            }
            total_bytes_sent += self.send(to, data).await?;
        }
        Ok(total_bytes_sent)
    }

    fn recv(&mut self, from: usize) -> impl Future<Output = io::Result<(Vec<u8>, RecvLen)>> {
        let channel = self.get_channel_mut(from);
        async move {
            let channel = channel?;
            channel
                .recv()
                .map_err(|e| io::Error::other(format!("Failed to receive from {}: {}", from, e)))
                .await
        }
    }

    fn recv_objects_many<'a, T, I>(
        &mut self,
        request: I,
    ) -> impl Future<Output = io::Result<(Vec<Vec<T>>, RecvLen)>>
    where
        T: for<'de> Deserialize<'de> + 'a,
        I: IntoIterator<Item = &'a ReceiveRequest<T>>,
    {
        let mut total_requests_len: usize = 0;

        let request_per_from = request
            .into_iter()
            .enumerate()
            .map(|(index, req)| {
                total_requests_len += 1;
                (req.from, (index, req.count))
            })
            .into_group_map();
        let total_requests_len = total_requests_len;

        let mut tasks = Vec::with_capacity(total_requests_len);

        let results = Arc::new(Mutex::new(
            (0..total_requests_len).map(|_| None).collect::<Vec<_>>(),
        ));

        let mut channel_extract_result = Ok(());
        for (from, counts) in request_per_from {
            let channel = self.channels.get_mut(from).and_then(Option::take);

            if channel.is_none() {
                channel_extract_result = Err(io::Error::other(format!(
                    "Channel {} unavailable or in use",
                    from
                )));
                break;
            }
            let mut channel: SecureStream<TcpStream> = channel.unwrap();

            let results = results.clone();

            let task = async move {
                let mut total_received_len = 0;
                for (index, count) in counts {
                    let (objects, received_len) = channel.recv_objects::<T>(count).await?;

                    let mut guard = results.lock().ok().unwrap();
                    let prev = guard[index].replace(objects);
                    assert!(prev.is_none());

                    total_received_len += received_len;
                }
                Ok::<_, io::Error>((total_received_len, from, channel))
            };

            tasks.push(task);
        }

        async move {
            channel_extract_result?;
            let mut received_len = 0;
            let async_results = future::try_join_all(tasks).await?;
            for (len, from, channel) in async_results {
                assert!(self.channels[from].is_none());
                self.channels[from] = Some(channel);
                received_len += len;
            }
            let results = Arc::try_unwrap(results).ok().unwrap().into_inner().unwrap();

            assert!(results.iter().all(|x| x.is_some()));

            let results = results.into_iter().collect::<Option<Vec<_>>>().unwrap();
            Ok((results, received_len))
        }
    }

    fn send_objects_many<'a, T, I>(
        &mut self,
        request: I,
    ) -> impl Future<Output = io::Result<SendLen>>
    where
        T: Serialize + 'a,
        I: IntoIterator<Item = &'a SendRequest<'a, T>>,
    {
        let mut total_request_len = 0;
        let request_per_to = request
            .into_iter()
            .map(|req| {
                total_request_len += 1;
                (req.to, &req.data)
            })
            .into_group_map();
        let mut tasks = Vec::with_capacity(total_request_len);

        struct RefList<'b, 'a, T>(&'b [&'b OwnedOrRef<'a, T>]);
        impl<'b, 'a, T: Serialize> Serialize for RefList<'b, 'a, T> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for item in self.0 {
                    match *item {
                        OwnedOrRef::Owned(t) => seq.serialize_element(t)?,
                        OwnedOrRef::Ref(t) => seq.serialize_element(*t)?,
                    }
                }
                seq.end()
            }
        }

        let mut channel_extract_result = Ok(());
        for (to, data) in request_per_to {
            let channel = self.channels.get_mut(to).and_then(Option::take);

            if channel.is_none() {
                channel_extract_result = Err(io::Error::other(format!(
                    "Channel {} unavailable or in use",
                    to
                )));
                break;
            }
            let mut channel: SecureStream<TcpStream> = channel.unwrap();

            let bytes_result = postcard::to_stdvec(&RefList(&data))
                .map_err(|e| io::Error::other(format!("Serialization error: {}", e)));

            let bytes = match bytes_result {
                Ok(b) => b,
                Err(e) => {
                    channel_extract_result = Err(e);
                    break;
                }
            };

            let task = async move {
                let len = channel.send(&bytes).await?;
                Ok::<_, io::Error>((len, to, channel))
            };

            tasks.push(task);
        }

        async move {
            channel_extract_result?;
            let mut send_len = 0;
            for (len, to, channel) in future::try_join_all(tasks).await? {
                send_len += len;
                assert!(self.channels[to].is_none());
                self.channels[to] = Some(channel);
            }
            Ok(send_len)
        }
    }
}

impl MeshNetwork {
    fn get_channel_mut(&mut self, target: usize) -> io::Result<&mut SecureStream<TcpStream>> {
        if target >= self.n_parties {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid Party ID",
            ));
        }

        match self.channels[target].as_mut() {
            Some(conn) => Ok(conn),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("No connection to Node {target} (or target is self)"),
            )),
        }
    }

    pub async fn from_identities(
        my_id: usize,
        my_secret_key: SigningKey,
        identities: NodeIdentities,
    ) -> anyhow::Result<Self> {
        use tokio::net::TcpListener;

        let n_parties = identities.len();
        let identities = Arc::new(identities);

        let listener_handle = {
            let listener = TcpListener::bind(identities[my_id].address).await?;
            let expected_incoming = n_parties - 1 - my_id;
            let my_secret_key = my_secret_key.clone();
            let identities = identities.clone();

            async move {
                let mut connections: Vec<Option<SecureStream<TcpStream>>> =
                    (0..n_parties).map(|_| None).collect();
                for _ in 0..expected_incoming {
                    let (mut stream, _) = listener.accept().await?;

                    let mut id_buf = [0_u8; 8];
                    stream.read_exact(&mut id_buf).await?;

                    let peer_id = u64::from_be_bytes(id_buf) as usize;
                    let peer_verifying_key = identities[peer_id].public_key;
                    let secure_stream = SecureStream::perform_handshake(
                        stream,
                        &my_secret_key,
                        &peer_verifying_key,
                        ConnectionRole::Listener,
                    )
                    .await?;

                    if connections[peer_id].replace(secure_stream).is_some() {
                        return Err(io::Error::other(format!(
                            "Node {}: Duplicate connection from Node {}",
                            my_id, peer_id
                        )));
                    }

                    if peer_id < my_id {
                        return Err(io::Error::other(format!(
                            "Node {}: Did not expect connection from Node {}",
                            my_id, peer_id
                        )));
                    }
                }
                Ok::<_, io::Error>(connections)
            }
        };

        let mut connector_handles = Vec::with_capacity(my_id);

        for target_id in 0..my_id {
            let target_address = identities[target_id].address;
            let target_verifying_key = identities[target_id].public_key;
            let my_secret_key = my_secret_key.clone();

            let handle = async move {
                loop {
                    let my_secret_key_clone = my_secret_key.clone();

                    let try_establish = async {
                        let mut stream = TcpStream::connect(target_address).await?;
                        let my_id_bytes = u64::to_be_bytes(my_id as u64);
                        stream.write_all(&my_id_bytes).await?;
                        let secure_stream = SecureStream::perform_handshake(
                            stream,
                            &my_secret_key_clone,
                            &target_verifying_key,
                            ConnectionRole::Initiator,
                        )
                        .await?;
                        Ok::<SecureStream<TcpStream>, anyhow::Error>(secure_stream)
                    };

                    match try_establish.await {
                        Ok(secure_stream) => {
                            break (target_id, secure_stream);
                        }
                        Err(_) => {
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        }
                    }
                }
            };

            connector_handles.push(handle);
        }

        let (listener_result, connector_results) = futures::join!(
            listener_handle,
            futures::future::join_all(connector_handles)
        );

        let mut connections = listener_result?;

        for (target, secure_stream) in connector_results {
            assert!(target < my_id);
            let prev = connections[target].replace(secure_stream);
            assert!(prev.is_none());
        }

        Ok(Self {
            my_id,
            n_parties,
            channels: connections,
        })
    }
}
